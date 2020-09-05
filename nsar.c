/*
    nsar : a Network nameSpace Aware tcp Redirector
    Copyright (C) 2019 Bertrand MAUJEAN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    A copy of the GNU GPLv3 License is included in the LICENSE.txt file
    You can also see <https://www.gnu.org/licenses/>.
*/


/**
 * \file nsar.c Main program file
 * \todo
 * - gérer ecriture incomplète
 * - gérer socket pas prêt en écriture
 * - mode daemon
 * - fichier log
 * - arrêt/signal
 * - revision G des erreurs, dont non bloquantes
 * - rendre dynamique MAXCONN et BUFSIZE
 * - Utiliser le netns de base du process plutot que celui d'init (=garder un handle dès le début)
 * - utiliser un thread pour les journaux, et ajouter la résolution DNS reverse
 * - utiliser un thread pour la boucle poll(), et faire les connect() dans un autre thread
 * - utiliser une focntion externe pour gérer l'association IP entrante->IP cible
 * - Générer des enregistrements pcap ou autre format adaptés au tcp
 */



#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <stdint.h>
#include <stdbool.h>

#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h> /* pour getaddrinfo() et compagnie */

#include <assert.h>
#include <string.h>
#include <unistd.h> /* read/write */

#include <netdb.h>  /* struct addrinfo */
#include <linux/in6.h>

#include <fcntl.h> /* open() */

#include <time.h>

#include <sched.h> /* CLONE_NEWNET */

// Nombre maximum de connections redirigeables simultanément
#define MAXCONN 64

// Taille du buffer de lecture/écriture
#define BUFSIZE 4096

int compteur_serial = 0; // sera incrémenté à chaque accept(), pour avoir un n° unique par connexion, pour les logs


// Défini en variable global, fixé par la lecture ligne de commande et utilisé dans main()
char* addr_ecoute_s = NULL;
char* port_ecoute_s = NULL;
char* addr_source_s = NULL;
char* addr_cible_s  = NULL;
char* port_cible_s  = NULL;
char* netns_entrant = NULL;
char* netns_sortant = NULL;

pid_t mon_pid = 0;

typedef struct connexion_active_s {
	int sock_entrant;
	int sock_sortant;
	uint64_t octets_in; // convention : = reçu du socket entrant
	uint64_t octets_out; //             = reçu du socket sortant
	bool detection_fin; // mis à true si read() renvoie 0, ce qui est une condition de fin du socket
	int serial; // numéro de série (compteur depuis lancement du programme)
	time_t start_time;
} connexion_active_t;





void journal_nelle_connexion(int entrant, int sortant, int serial) {
	struct sockaddr_in6 sa_local_entrant, sa_local_sortant;
	socklen_t sal_local_entrant, sal_local_sortant;

	struct sockaddr_in6 sa_dist_entrant, sa_dist_sortant;
	socklen_t sal_dist_entrant, sal_dist_sortant;

	char fqdn_local_entrant[64], fqdn_local_sortant[64], service_local_entrant[20], service_local_sortant[20];
	char fqdn_dist_entrant[64], fqdn_dist_sortant[64], service_dist_entrant[20], service_dist_sortant[20];

	sal_local_entrant = sal_local_sortant = sizeof(struct sockaddr_in6);
	sal_dist_entrant = sal_dist_sortant = sizeof(struct sockaddr_in6);

	int err = getsockname(entrant, (struct sockaddr*)&sa_local_entrant, &sal_local_entrant);
	if (err) {
		perror("getsockname() dans journal_nelle_connexion()");

	} else {
		err=getnameinfo((struct sockaddr*)&sa_local_entrant, sal_local_entrant, fqdn_local_entrant, 63, service_local_entrant, 19, NI_NUMERICHOST|NI_NUMERICSERV);
		if (err) {
			perror("getnameinfo() dans journal_nelle_connexion()");
		}
	}

	err = getsockname(sortant, (struct sockaddr*)&sa_local_sortant, &sal_local_sortant);
	if (err) {
		perror("getsockname() dans journal_nelle_connexion()");
	} else {
		err=getnameinfo((struct sockaddr*)&sa_local_sortant, sal_local_sortant, fqdn_local_sortant, 63, service_local_sortant, 19, NI_NUMERICHOST|NI_NUMERICSERV);
		if (err) {
			perror("getnameinfo() dans journal_nelle_connexion()");
		}
	}


	err = getpeername(entrant, (struct sockaddr*)&sa_dist_entrant, &sal_dist_entrant);
	if (err) {
		perror("getsockname() dans journal_nelle_connexion()");


	} else {
		err=getnameinfo((struct sockaddr*)&sa_dist_entrant, sal_dist_entrant, fqdn_dist_entrant, 63, service_dist_entrant, 19, NI_NUMERICHOST|NI_NUMERICSERV);
		if (err) {
			perror("getnameinfo() dans journal_nelle_connexion()");
		}
	}

	err = getpeername(sortant, (struct sockaddr*)&sa_dist_sortant, &sal_dist_sortant);
	if (err) {
		perror("getsockname() dans journal_nelle_connexion()");
	} else {
		err=getnameinfo((struct sockaddr*)&sa_dist_sortant, sal_dist_sortant, fqdn_dist_sortant, 63, service_dist_sortant, 19, NI_NUMERICHOST|NI_NUMERICSERV);
		if (err) {
			perror("getnameinfo() dans journal_nelle_connexion()");
		}
	}

	printf("event=new_connexion pid=%d id_cnx=%d ", mon_pid, serial);
	printf("in-local=%s/%s out-local=%s/%s ", fqdn_local_entrant, service_local_entrant, fqdn_local_sortant, service_local_sortant);
	printf("in-dist=%s/%s out-dist=%s/%s\n", fqdn_dist_entrant,  service_dist_entrant,  fqdn_dist_sortant,  service_dist_sortant);
}

void journal_fin_connexion(connexion_active_t* c) {
	time_t d=time(NULL)-c->start_time;
	printf("event=end_connexion pid=%ld id=%d inb=%ld outb=%ld duration=%ld\n", mon_pid, c->serial, c->octets_in, c->octets_out, d);
}


void journal_demarrage() {
	mon_pid = getpid();
	printf("event=startup pid=%d ", mon_pid);
	printf("incoming-service=%s ", port_ecoute_s);
	printf("outgoing-address=%s outgoing-service=%s ", addr_cible_s, port_cible_s);
	printf("bind-listen=%s bind-connect=%s ", addr_ecoute_s, addr_source_s);
	printf("incoming-netns=%s outgoing-netns=%s ", netns_entrant, netns_sortant);
	printf("\n");
}

void journal_arret() {
	printf("event=shutdown pid=%d ", mon_pid);
}

void change_netns(char *ns)  {

	// Cas où aucun netns n'est spécifié : ne fait rien du tout
	// reste éventuellement dans le ns dans lequel on était en lançant le programme
	if ((netns_entrant == NULL) && (netns_sortant == NULL)) return;


	char* bind_ns = alloca(256); // nom complet du bound ns à ouvrir avec open()

	if (ns == NULL) {
	// Cas où on veut se remettre dans le netns par défaut. On va prendre celui de 'init'
		bind_ns = "/proc/1/ns/net";
	} else {
		snprintf(bind_ns, 255, "/var/run/netns/%s", ns);
	}

	int fd = open(bind_ns, O_RDONLY);
	if (fd < 0) {
		printf("Error : cannot open namespace %s. Aborting", bind_ns);
		perror("");
		assert(0);
	}

	int err = setns(fd, 0); // CLONE_NEWNET : je ne retrouve pas le header qui va bien...
	if (err <0) {
		perror("Error : setns() ");
		assert(0);
	}
}




void do_loop(int listening_socket,
		     struct sockaddr *sock_source,  socklen_t sock_source_len,
			 struct sockaddr *sock_cible,   socklen_t sock_cible_len) {

	struct pollfd poller[2*MAXCONN+1]; // +1 pour le socket d'écoute

    connexion_active_t connexions[MAXCONN];
    int nb_connexions = 0;

    char* buffer = malloc(BUFSIZE);
    assert(buffer!=0);


	while(1) {

		// Prépare la liste des sockets à passer à poll()

		//printf("%d connexions actives\n", nb_connexions);

		memset(poller, 0, sizeof(poller));
		for (int i=0; i<nb_connexions; i++) {
			poller[2*i].fd   = connexions[i].sock_entrant;
			poller[2*i].events = POLLIN;
			poller[2*i+1].fd = connexions[i].sock_sortant;
			poller[2*i+1].events = POLLIN;
			//printf("surveille %d et %d\n",connexions[i].sock_entrant , connexions[i].sock_sortant);
		}
		poller[2*nb_connexions].fd = listening_socket;
		poller[2*nb_connexions].events = POLLIN | POLLPRI;


		//printf("listening socket=%d nb_connexions=%d\n", listening_socket, nb_connexions);

		// Poll()
		int res_poll = poll(poller, 2*nb_connexions+1, 10000);
		if (res_poll <0) {
			perror("Error : poll()");
			exit(1);
		}
		if (res_poll ==0) {
			//puts("poll() a fait un timeout");
			continue;
		}
		//printf("poll() retourne %d\n", res_poll);

		// Vérifie si un socket doit être accepté
		if (poller[2*nb_connexions].revents & POLLIN ) {
			if  (nb_connexions<MAXCONN) { // Nb : si maxconn, alors accept pas fait donc attente...
				// Ici, fait l'entrée d'une nouvelle connexion
				memset(&connexions[nb_connexions], 0, sizeof(connexion_active_t));

				//puts("accept() :");
				int entrant = accept(listening_socket, NULL, NULL);

				change_netns(netns_sortant);

				int sortant = socket(AF_INET6, SOCK_STREAM, 0);
				if (sortant < 0) {
					perror("socket() sortant");
					exit(1);
				}
				int err = connect(sortant, sock_cible, sock_cible_len);
				if (err<0) {
					perror("Error : connect()");
					exit(1);
				}
				connexions[nb_connexions].sock_entrant = entrant;
				connexions[nb_connexions].sock_sortant = sortant;
				connexions[nb_connexions].serial = compteur_serial;
				connexions[nb_connexions].start_time = time(NULL);

				journal_nelle_connexion(entrant, sortant, compteur_serial);

				compteur_serial++;
				nb_connexions++;
				continue; // Car sinon, comme nb_connexion a été manipulé, la suite bloque...
			} else {
				printf("event=max_cnx pid=%ld \n", mon_pid);
			}
		}



		// Vérifie si un socket entrant est disponible en lecture
		for (int i=0; i<nb_connexions; i++) if (poller[2*i].revents & POLLIN) {
			//puts("avant read()\n");
			ssize_t noctets = read(connexions[i].sock_entrant, buffer, BUFSIZE);
			//puts("apres read() avant write()\n");
			if (noctets) {
				write(connexions[i].sock_sortant, buffer, noctets);
				connexions[i].octets_in += noctets;
			} else
				connexions[i].detection_fin = true;
			//puts("apres write()\n");
		}

		// Vérifie si un socket sortant est disponible en lecture
		for (int i=0; i<nb_connexions; i++) if (poller[2*i+1].revents & POLLIN) {
			//puts("Données dispo sur socket sortant");
			ssize_t noctets = read(connexions[i].sock_sortant, buffer, BUFSIZE);
			//printf("buff=%p lu=%ld\n", buffer, noctets);
			if (noctets <0) { perror(""); exit(1); }

			if (noctets) {
				write(connexions[i].sock_entrant, buffer, noctets);
				connexions[i].octets_out += noctets;
			} else
				connexions[i].detection_fin = true;
		}

		// Vérifie si un socket entrant ou sortant est fermé
		for (int i=0; i<nb_connexions; i++)
			if ((poller[2*i+1].revents & (POLLHUP|POLLERR)) ||
				(poller[2*i].revents   & (POLLHUP|POLLERR)) ||
				(connexions[i].detection_fin)   				) {

			//puts("fin de connexion");
			journal_fin_connexion(&connexions[i]);
			close(connexions[i].sock_entrant);
			close(connexions[i].sock_sortant);
			// Supprime la connexion n° i
			for (int j=i; j<nb_connexions-1; j++) {
				connexions[j]=connexions[j+1]; // recopie de struct !
			}
			nb_connexions--;
		}
	} // while(1)

}





/**
 * Affichage de l'aide
 */
void usage(char* argv0) {
	printf("%s <args>\n", argv0);

	puts("\nMandatory parameters :");
	puts("\t--incoming-service <service|port number>: associated service / TCP port number");
	puts("\t--outgoing-address <address> : address to forward connexino to");
	puts("\t--outgoing-service <service|port number> : associated service / TCP port number");

	puts("\nOptionnal parameters : local address binding");
	puts("\t--bind-listen <address> : local address to bind to for listening for incoming connexions");
	puts("\t--bind-connect <address> : local address to bind to for connecting outgoing connexions");

	puts("\nOptionnal parameters : network namespaces");
	puts("\t--incoming-netns <namespace name>");
	puts("\t--outgoing-netns <namespace name>");
	puts("\tNote : if no netns is specified, the program will not do any setns() call, remaining in current netns");
	puts("\t       if a leat one of the netns is specified, then netns operation is enable, and then :");
	puts("\t       - program need CAP_SYS_ADMIN or root privileges");
	puts("\t       - a non specified namespace correspond to default namespace, the one of init/pid=1 process");

	puts("\nOther optionnal parameters");
	puts("\t--buffer-size <size in bytes>");
	puts("\t--log-file <log file name>");
	puts("\tNote on log format : the program will never do reverse DNS resolution because it is single-threaded, and can not afford to wait for DNS lookup");

	exit(0);
}

/**
 * Lecture de la ligne de commande
 */
void ligne_de_commande(int argc, char *argv[]) {
	struct option long_options[] = {

		{
			.name = "incoming-service",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 2
		},
		{
			.name = "outgoing-address",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 3
		},
		{
			.name = "outgoing-service",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 4
		},
		{
			.name = "bind-listen",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 5
		},
		{
			.name = "bind-connect",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 6
		},
		{
			.name = "incoming-netns",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 7
		},
		{
			.name = "outgoing-netns",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 8
		},
		{
			.name = "buffer-size",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 9
		},
		{
			.name = "log-file",
			.has_arg=required_argument,
			.flag = NULL,
			.val = 10
		},
		{
			.name = "",
			.has_arg=0,
			.flag = NULL,
			.val = 0
		}
	};

	opterr = 0;
	int o;

	while(   (o=getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		if (o==63) {
			printf("Error : Unkown option Aborting.\n\n");
			usage(argv[0]);
			exit(0);
		}

		switch (o) {
			case  2: // incoming-service
				port_ecoute_s = strdup(optarg);
				break;

			case  3: // outgoing-address
				addr_cible_s = strdup(optarg);
				break;

			case  4: // outgoing-service
				port_cible_s  = strdup(optarg);
				break;

			case  5: // bind-listen
				addr_ecoute_s = strdup(optarg);
				break;

			case  6: // bind-connect
				addr_source_s = strdup(optarg);
				break;

			case  7: // incoming-netns
				netns_entrant = strdup(optarg);
				break;

			case  8: // outgoing-netns
				netns_sortant = strdup(optarg);
				break;

			case  9: // buffer-size
				puts("buffer-size pas implémenté");
				break;

			case 10: // log-file
				puts("log-file pas implémenté");
				break;

		} // switch
	}



	if (port_ecoute_s == NULL) {
		puts("Error : --incoming-service is mandatory. Aborting.");
		usage(argv[0]);
		exit(0);
	}

	if (addr_cible_s == NULL) {
		puts("Error : --outgoing-address is mandatory. Aborting.");
		usage(argv[0]);
		exit(0);
	}
	if (port_cible_s == NULL) {
		puts("Error : --outgoing-service is mandatory. Aborting.");
		usage(argv[0]);
		exit(0);
	}

	/*
	printf("port_ecoute_s=%s\n",port_ecoute_s);
	printf("addr_cible_s =%s\n",addr_cible_s);
	printf("port_cible_s =%s\n",port_cible_s);
	printf("addr_ecoute_s=%s\n",addr_ecoute_s);
	printf("addr_source_s=%s\n",addr_source_s);
	*/
}




int prepare_socket_ecoute() {
	struct sockaddr* sock_ecoute;
	socklen_t sock_ecoute_len;

	// Prépare le socket d'écoute
	struct addrinfo* ai;
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_flags = (AI_PASSIVE | AI_V4MAPPED);
	hints.ai_family=AF_INET6;
	hints.ai_socktype=SOCK_STREAM;
	int err = getaddrinfo(addr_ecoute_s, port_ecoute_s, &hints, &ai);
	if (err != 0) {
		perror("Error : getaddrinfo()");
		puts(gai_strerror(err));
		printf("Listening socket %s : %s\n", addr_ecoute_s, port_ecoute_s );
		assert(0);
	}

	sock_ecoute_len = ai->ai_addrlen;
	sock_ecoute = malloc(sock_ecoute_len);
	assert(sock_ecoute);
	memcpy(sock_ecoute, ai->ai_addr, sock_ecoute_len);
	freeaddrinfo(ai);


	// Affichage de l'adresse d'écoute
	/*
	char a[32];
	char s[32];
	getnameinfo(sock_ecoute, sock_ecoute_len, a, 32, s, 32, NI_NUMERICHOST | NI_NUMERICSERV);
	printf("ecoute sur %s %s\n", a, s);
	*/


    // Ouvre le socket d'écoute AF_INET6 prend en charge IPv4 et IPv6
	change_netns(netns_entrant);
    int listening_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (listening_socket<0) {
    	perror("Error : socket() failed");
    	assert(0);
    }

    // Permet au socket d'écoute d'être réutilisé rapidement quand le serveur est relancé
    int on=1;
    if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on)) < 0) {
    	perror("setsockopt(SO_REUSEADDR) failed");
    	assert(0);
    }

    if (bind(listening_socket, (struct sockaddr *)sock_ecoute, sock_ecoute_len) <0) {
    	perror("Error : bind()");
    	assert(0);
    }

    if (listen(listening_socket, 5)<0) {
    	perror("Error : listen()");
    	assert(0);
    }

    return listening_socket;
}

void prepare_socket_source(struct sockaddr** sock_source_, socklen_t* sock_source_len_ ) {
	struct sockaddr* sock_source;
	socklen_t sock_source_len;

	struct addrinfo* ai;

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_V4MAPPED;
	hints.ai_family=AF_INET6;

	// Prépare le socket source
	if (addr_source_s) {
		int err = getaddrinfo(addr_source_s, NULL, NULL, &ai); // service=NULL car on prend un port dynamique
		if (err != 0) {
			perror("Error : getaddrinfo()");
			puts(gai_strerror(err));
			printf("Source socket %s\n", addr_source_s );
			exit(1);
		}
		sock_source_len = ai->ai_addrlen;
		sock_source = malloc(sock_source_len);
		assert(sock_source);
		memcpy(sock_source, ai->ai_addr, sock_source_len);
		freeaddrinfo(ai);

	} else {
		sock_source = NULL; /* do_loop() ne fera pas le bind() avant le connect() */
		sock_source_len =0;
	}

	*sock_source_ = sock_source;
	*sock_source_len_ = sock_source_len;
}

void prepare_socket_cible(struct sockaddr** sock_cible_, socklen_t* sock_cible_len_ ) {
	struct sockaddr* sock_cible;
	socklen_t sock_cible_len;

	struct addrinfo* ai;
	struct addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_V4MAPPED;
	hints.ai_family=AF_INET6;
	hints.ai_socktype=SOCK_STREAM;

	int err = getaddrinfo(addr_cible_s, port_cible_s, &hints, &ai);
	if (err != 0) {
		perror("Error : getaddrinfo()");
		puts(gai_strerror(err));
		printf("Target socket %s : %s\n", addr_cible_s, port_cible_s );
		assert(0);
	}
	sock_cible_len = ai->ai_addrlen;
	sock_cible = malloc(sock_cible_len);
	assert(sock_cible);
	memcpy(sock_cible, ai->ai_addr, sock_cible_len);
	freeaddrinfo(ai);
	// Affichage de l'adresse d'écoute
	char a[32];
	char s[32];
	getnameinfo(sock_cible, sock_cible_len, a, 32, s, 32, NI_NUMERICHOST | NI_NUMERICSERV);
	//printf("Cible sur %s %s\n", a, s);

	*sock_cible_     = sock_cible;
	*sock_cible_len_ = sock_cible_len;
}

int main(int argc, char *argv[]) {
	ligne_de_commande(argc,argv);

	journal_demarrage();

	struct sockaddr* sock_source;
	socklen_t sock_source_len;
	struct sockaddr* sock_cible;
	socklen_t sock_cible_len;

	int listening_socket = prepare_socket_ecoute();
	prepare_socket_source(&sock_source, &sock_source_len);
	prepare_socket_cible (&sock_cible,  &sock_cible_len);

	do_loop(listening_socket, sock_source, sock_source_len, sock_cible, sock_cible_len);

	journal_arret();

	return 0;
}

