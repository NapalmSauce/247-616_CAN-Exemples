#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <wait.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <inttypes.h>

int main(int argc, char *argv[]) //char **argv)
{
	int fdSocketCAN, i; 
	int nbytes;
	struct sockaddr_can addr;
	struct ifreq ifr;
	struct can_frame frame;
  
  pid_t pid;

	printf("boop\r\n");

	/*
	La première étape est de créer un socket. 
	Cette fonction accepte trois paramètres : 
		domaine/famille de protocoles (PF_CAN), 
		type de socket (raw ou datagram) et 
		protocole de socket. 
	la fonction retourne un descripteur de fichier.
	*/
	if ((fdSocketCAN = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("Socket");
		return -1;
	}
	
	/*
	Ensuite, récupérer l'index de l'interface pour le nom de l'interface (can0, can1, vcan0, etc.) 
	que nous souhaitons utiliser. Envoyer un appel de contrôle d'entrée/sortie et 
	passer une structure ifreq contenant le nom de l'interface 
	*/
	if(argc == 2)
		strcpy(ifr.ifr_name, argv[1]);
	else strcpy(ifr.ifr_name, "vcan0" );

	ioctl(fdSocketCAN, SIOCGIFINDEX, &ifr);
	/* 	Alternativement, zéro comme index d'interface, permet de récupérer les paquets de toutes les interfaces CAN.
	Avec l'index de l'interface, maintenant lier le socket à l'interface CAN
	*/

	/*
	
	*/
	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	if (bind(fdSocketCAN, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Bind");
		return -1;
	}
  
  pid = fork();
  
  if(!pid)
  {
    char mystr[9];
    unsigned char len;
 
struct can_filter rfilter[3];

    rfilter[0].can_id = 0xFFF;
    rfilter[0].can_mask = 0x123;


    rfilter[1].can_id = 0xFFF;
    rfilter[1].can_mask = 0x124;

    rfilter[2].can_id = 0xFFF;
    rfilter[2].can_mask = 0x007;


//    setsockopt(fdSocketCAN, SOL_CAN_RAW, CAN_RAW_FILTER, rfilter, sizeof(rfilter));
//    setsockopt(fdSocketCAN, SOL_CAN_RAW, CAN_RAW_FILTER, rfilter, sizeof(rfilter));

   while(1)
    {
      // appel système read(). Cela bloquera jusqu'à ce qu'une trame soit disponible
      nbytes = read(fdSocketCAN, &frame, sizeof(struct can_frame));

      if (nbytes < 0) {
        perror("Read");
        return -1;
      }

      printf("0x%03X [%d] ",frame.can_id, frame.can_dlc);
      for (i = 0; i < frame.can_dlc; i++)
        printf("%02X ",frame.data[i]);
      len = frame.can_dlc;
      memcpy(mystr,frame.data,8);
      mystr[len] = '\0';
      putchar('\"');
      printf(mystr);
      putchar('\"');
      putchar('\n');

    }
  }
  else if(pid > 0)
  {
    char mystr[10];
    unsigned char len = 1;
    while(len)
    {
      /*
      Envoyer une trame CAN, initialiser une structure can_frame et la remplir avec des données. 
      La structure can_frame de base est définie dans include/linux/can.h  
      */
      frame.can_id = 0x007;  	// identifiant CAN, exemple: 247 = 0x0F7
    //  frame.can_id = 0x460;  	// identifiant CAN, exemple: 247 = 0x0F7
    //   frame.can_dlc = 7;		// nombre d'octets de données
      
      fgets(mystr, 10, stdin);
      len = strlen(mystr) - 1;
     // frame.can_dlc = len;
      frame.can_dlc = 4;
      uint8_t boo[] = {0x01,0x02,0x03,0x04};
      
      // memcpy(frame.data,mystr,len);
      memcpy(frame.data,boo,4);

      if(len != 0)
      {
//	if (write(fdSocketCAN, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
	if (write(fdSocketCAN, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame))
	{
	  perror("Write");
	  return -1;
	}
      }
    }
    
    wait(NULL);
  }
  else
  {
    fprintf(stderr,"Erreur de creation du processus fils");
  }
  
  
  if (close(fdSocketCAN) < 0) {
    perror("Close");
    return -1;
  } 
    
  return 0;
}
