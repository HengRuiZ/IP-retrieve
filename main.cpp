#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#define REDIRECT_MODE_1 0x01
#define REDIRECT_MODE_2 0x02
using namespace std;
FILE*fp;
int strcmp_u(unsigned char c[4],unsigned char d[4])//比较无符号字符串 
{
	unsigned char i;
	for(i=0;i<4;i++)
	if(c[i]>d[i])
	return 1;
	else if(c[i]<d[i])
	return -1;
	return 0;
}
int IPIndex(unsigned char c[4])//根据IP位置查找索引位置 
{
	int a,b,i,mid;
	unsigned char d[4],e;
	fseek(fp,0,0);
	fread(&a,4,1,fp);
	fread(&b,4,1,fp);//找到文件索引部分 
	while(a<=b){	//二分法 
		mid=a+(b-a)/7/2*7;
		//printf("%d,%d,%d	",a,b,mid);//显示当前参数 
		fseek(fp,mid,0);
		for(i=0;i<4;i++)
		d[3-i]=fgetc(fp);
		//printf("%u.%u.%u.%u\n",d[0],d[1],d[2],d[3]);//显示当前IP值 
		//fseek(fp,-4,1);//还原指针 
		switch(strcmp_u(c,d)){
			case 1:{
				a=mid+7;
				break;
			}
			case -1:{
				b=mid-7;
				break;
			}
			case 0:{
				e=fgetc(fp);i=e;
				e=fgetc(fp);i+=e*256;
				e=fgetc(fp);i+=e*256*256;
				//printf("%u.%u.%u.%u\n",d[0],d[1],d[2],d[3]);//显示起始IP 
				return i-7;
				break;
			}
		}
	}
	fseek(fp,b-3,0);//两种情况(b-7或者a+7导致b<a)下IP索引位置均为b 
	e=fgetc(fp);i=e;
	e=fgetc(fp);i+=e*256;
	e=fgetc(fp);i+=e*256*256;
	printf("%u.%u.%u.%u\n",d[0],d[1],d[2],d[3]);//显示起始IP 
	return i;
}
void ReDirect(int deviant)//重定向函数，适用于模式1和模式2无限嵌套 
{
	int i;
	char mode,adr[100];
	unsigned char c[3];
	fseek(fp,deviant,0);
	mode=fgetc(fp);
	switch(mode){
		case REDIRECT_MODE_1:{
			for(i=0;i<3;i++)
			c[i]=fgetc(fp);
			i=c[0]+c[1]*256+c[2]*256*256;
			if(i)
			ReDirect(i);
			else
			cout<<"未知地区名"<<endl; 
			break;
		}
		case REDIRECT_MODE_2:{
			for(i=0;i<3;i++)
			c[i]=fgetc(fp);
			i=c[0]+c[1]*256+c[2]*256*256;
			if(i)
			ReDirect(i);
			else
			cout<<"未知地区名"<<endl;
			ReDirect(deviant+4);
			break;
		}
		default:{
			adr[0]=mode;
			for(i=1;(adr[i]=fgetc(fp))!='\0';i++);
			printf("%s\n",adr);
		}
	}
}
int IPRecord(int a,unsigned char c[4])//显示IP记录 
{
	unsigned char d[4];
	char rec[100];
	int i;
	fseek(fp,a,0);
	for(i=0;i<4;i++)
	d[3-i]=fgetc(fp);
	printf("%u.%u.%u.%u\n",d[0],d[1],d[2],d[3]);//显示结束IP 
	//if(strcmp_u(c,d)>0)
	//return 0;
	ReDirect(a+4);
}
int main(int argc, char** argv) {
	int a,b,d,i,j;
	unsigned char c[4];
	if((fp=fopen("qqwry.dat","rb"))==NULL)
	{
		cout<<"打开文件失败！"<<endl;
		exit(0);
	}
	/*fread(&a,4,1,fp);
	fseek(fp,a,0);
	for(i=0;i<100;i++)
	{
		for(j=0;j<7;j++)
		{
			c[0]=fgetc(fp);
			printf("%u	",c[0]);
		}
		printf("\n");
	}*/	//显示索引记录格式 
	cout<<"请输入IP"<<endl;
	scanf("%u.%u.%u.%u",c,c+1,c+2,c+3);
	d=IPRecord(IPIndex(c),c);
	if(d==0){
		printf("查找失败\n");
	}
	fclose(fp);
	system("pause");
	return 0;
}
