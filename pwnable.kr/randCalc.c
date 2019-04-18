#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main(int argc, char *argv[])
{
  //time_t t = time(0);

  int t=atoi(argv[1]);
  int m=atoi(argv[2]);

  srand(t);
  int num[32];
  for (int i=0;i<=7;i++)
  {
    num[i*4]=rand();
    //printf ("num[%d]:%x\n",i*4, num[i*4]);
  }
  int tot = (num[4]+num[20])+(num[8]-num[12])+(num[28])+(num[16]-num[24]);
  m -= tot;
  printf ("%x\n",m);
  return 0;
}
