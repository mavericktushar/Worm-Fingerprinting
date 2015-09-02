#include "worm_fingerprinting.h"

unsigned int RSHash(char *str,int sz)
{	
   int i;
   unsigned int b    = 378551;
   unsigned int a    = 63689;
   unsigned int hash = 0;

   for(i = 0; i < sz; i++)
   {
      hash = hash * a + str[i];
      a    = a * b;
   }

   return (hash & 0x7FFFFFFF);
}
/* End Of RS Hash Function */


unsigned int JSHash(char *str,int sz)
{
   int i;
   unsigned int hash = 1315423911;

   for(i = 0; i < sz; i++)
   {
      hash ^= ((hash << 5) + str[i] + (hash >> 2));
   }

   return (hash & 0x7FFFFFFF);
}

void detect_it(char *substring,char *src_ip_buf)
{
	int i;
	unsigned int rshash;
	unsigned int jshash;
	
/*	for(i=0;i<beta_sz;i++)
	{
		printf("%02x",substring[i]);
	}
	printf("\nsize :: %d",strlen(substring));
*/
	//memcpy((substring+beta_sz),'\0',1);

	rshash=RSHash(substring,beta_sz);
	jshash=JSHash(substring,beta_sz);
	
//	printf("\nRSHash of substring :: %d",rshash);
//	printf("\nJSHash of substring :: %d",jshash);

	int adisp_flag=0;
	int a_index=0;
	int c_index=0;

	int init_sign_found=0;
	
	for(i=0;i<sign_cnt;i++)
	{
		if((strcmp(substring,sign_table[i])==0))
		{
			init_sign_found=1;
			break;	
		}
	}

	if(init_sign_found==1)
	{
		printf("\nWorm entry found in signature table. No need to check further . . .");
		return;
	}

	for(i=0;i<65500;i++)
	{
		if((prvl_table[i].valid==1))
		{
			if((prvl_table[i].rshash_t==rshash))
			{	
				c_index=i;
				break;
			}
		}
	}

	for(i=0;i<65500;i++)
	{
		if((adisp_table[i].valid==1))
		{
			if((adisp_table[i].rshash_t==rshash))
			{
				adisp_flag=1;	
				a_index=i;
				break;
			}
		}
	}

	if(adisp_flag==1)
	{
		//ADT Entry
		
		time_t adt_time=time(NULL);
		
		if(((adt_time - prvl_table[c_index].entry_time)>TIME_THRESHOLD))
		{
			adisp_table[a_index].valid=0;
			adisp_table[a_index].ip_cnt=0;
	
			prvl_table[c_index].valid=1;
			//prvl_table[c_index].rshash_t=rshash;
			//prvl_table[c_index].jshash_t=jshash;
			prvl_table[c_index].rs_cnt=1;
			prvl_table[c_index].js_cnt=1;
			prvl_table[c_index].entry_time=time(NULL);

			return;			
		}

		printf("\nEntry found in address dispersion table . . . %s",substring);

		int entry_flag=0;
		for(int k=0;k<adisp_table[a_index].ip_cnt;k++)
		{
			if((strcmp(adisp_table[a_index].src_ip_addr[k],src_ip_buf)==0))
			{
				entry_flag=1;
				printf("\nip entry found in address dispersion table . . . %s. Distinct ip count :: %d",src_ip_buf,adisp_table[a_index].ip_cnt);
			}
		}
	
		if(entry_flag==0)
		{	
			strcpy(adisp_table[a_index].src_ip_addr[adisp_table[a_index].ip_cnt],src_ip_buf);
			adisp_table[a_index].ip_cnt++;

			printf("\nnew ip entry in address dispersion table . . . %s. Distinct ip count :: %d",src_ip_buf,adisp_table[a_index].ip_cnt);
			
			if(adisp_table[a_index].ip_cnt>=IP_THRESHOLD)
			{
				time_t current_time=time(NULL);
	
				//printf("current_time :: %ld",current_time);
				//printf("old time :: %ld",prvl_table[c_index].entry_time);
	
				if((current_time - prvl_table[c_index].entry_time) <= TIME_THRESHOLD)
				{
					int sign_flag=0;
					for(int k=0;k<sign_cnt;k++)
					{
						if((strcmp(sign_table[k],substring)==0))
						{
							sign_flag=1;
						}
					}

					if(sign_flag==0)
					{
						printf("\n*************************\nNew Worm Detected . . .\n**************************\n");
						strcpy(sign_table[sign_cnt],substring);
						sign_cnt++;
						printf("\nNew entry made in signature table . . . %d",rshash);
				
						//New Worm (iptable entries)
						char temp_str[(beta_sz+1)];
						strcpy(temp_str,substring);
						//temp_str[beta_sz]='\0';
						printf("\nWorm String :: %s",temp_str);
	
						char rule_str[200];
						memset(rule_str,'\0',200);
						
						//Input chain
						sprintf(rule_str,"iptables -I INPUT -j DROP -m string --string \"%s\" --algo bm",temp_str);
						system(rule_str);
						
						//Output chain
						sprintf(rule_str,"iptables -I OUTPUT -j DROP -m string --string \"%s\" --algo bm",temp_str);
						system(rule_str);

						//Forward chain
						sprintf(rule_str,"iptables -I FORWARD -j DROP -m string --string \"%s\" --algo bm",temp_str);
						system(rule_str);
	
						//save iptables
						sprintf(rule_str,"iptables-save > /etc/iptables-rule");
						system(rule_str);
					}
					else
					{
						printf("\nWorm Already detected . . .");
					}
				}
				else
				{
					printf("Worm detected. but timeout . . .");
				}
		
				prvl_table[c_index].valid=0;
				adisp_table[a_index].valid=0;

				return;
			}
			//printf("\nNew ip entry found in address dispersion table . . . %s",substring);
		}
		
		return;
	}

	//If entry not found in ADTinet_ntoa(ip->ip_src)
	int prvl_flag=0;
	int index=-1;
	for(i=0;i<65500;i++)
	{
		if((prvl_table[i].valid==1))
		{
			if((prvl_table[i].rshash_t==rshash))
			{
				prvl_flag=1;	
				index=i;
				break;
			}
		}
	}

	if(prvl_flag==1)
	{
		//Entry in Prevalence table
		time_t prev_time=time(NULL);
		if(((prev_time - prvl_table[index].entry_time)>TIME_THRESHOLD))
		{
			printf("\nNew entry in prevalence table . . . %s",substring);
			prvl_table[index].rs_cnt=1;
			prvl_table[index].js_cnt=1;
			prvl_table[index].entry_time=time(NULL);
		}
		else
		{
			prvl_table[index].rs_cnt++;
			if(prvl_table[index].jshash_t==jshash)
			{
				prvl_table[index].js_cnt++;
			}
			prvl_table[index].entry_time=time(NULL);
		
			int act_threshold;
			act_threshold=(prvl_table[index].rs_cnt > prvl_table[index].js_cnt) ? prvl_table[index].js_cnt : prvl_table[index].rs_cnt;

			printf("\nEntry found in prevalence table . . . %s. %d time . . .",substring,act_threshold);

			if(act_threshold>=THRESHOLD)
			{
				adisp_cnt=-1;

				for(i=0;i<65500;i++)
				{
					if(adisp_table[i].valid==0)
					{
						adisp_cnt=i;
						break;
					}
				}

				if(adisp_cnt<0)
				{
					printf("\nNo space in Address Dispersion table. Table full . . .");
					return;
				}

				adisp_table[adisp_cnt].valid=1;
				adisp_table[adisp_cnt].rshash_t=rshash;
				adisp_table[adisp_cnt].ip_cnt=1;
				strcpy(adisp_table[adisp_cnt].src_ip_addr[0],src_ip_buf);//,strlen(src_ip_buf));		//May not work because of strcpy or strlen of src_ip_buf
				adisp_cnt++;
				//prvl_table[index].valid=0;
				printf("\nPrevalence threshold reached for string :: %s . . .",substring);
				printf("\nMaking entry in Adress Dispersion Table . . .");
			}
		}
	}
	else
	{
		//New Entry
		printf("\nNew entry in prevalence table . . . %s",substring);

		prv_cnt=-1;

		for(i=0;i<65500;i++)
		{
			if(prvl_table[i].valid==0)
			{
				prv_cnt=i;
				break;
			}
		}

		if(prv_cnt<0)
		{
			printf("\nNo space in prevalence table. Table full . . .");
			return;
		}

		prvl_table[prv_cnt].valid=1;
		prvl_table[prv_cnt].rshash_t=rshash;
		prvl_table[prv_cnt].jshash_t=jshash;
		prvl_table[prv_cnt].rs_cnt=1;
		prvl_table[prv_cnt].js_cnt=1;
		prvl_table[prv_cnt].entry_time=time(NULL);
		prv_cnt++;		
	}	
		
}

void worm_detect_func(u_char *args,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	static int cnt=0;

	
	const struct sniff_ethernet *ether;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	u_char *payload=NULL;
	
	int ip_sz=0;
	int trans_sz=0;
	int payload_sz=0;
	int j;

	//printf("\n%d Packet captured . . . ",(cnt+1));
	//cnt++;

	ether=(struct sniff_ethernet *)(packet);		//Extract Ethernet header

	ip=(struct sniff_ip *)(packet+SIZE_ETHERNET);		//Extract IP header
	ip_sz=IP_HL(ip)*4;
//	printf("ip_sz :: %d",ip_sz);
	if(ip_sz<20)
	{
//		printf("\nError ip header less than 20 bytes . . .");
		return;
	}

	if((strcmp(inet_ntoa(ip->ip_src),"204.57.1.176")!=0))
	{
		switch(ip->ip_p)
		{
			case IPPROTO_TCP: {//printf("\nTransport layer Protocol TCP");
					  break;
					  }
			case IPPROTO_UDP: {//printf("\nTransport layer Protocol UDP");
					  return;
					  }
			case IPPROTO_ICMP: {//printf("\nTransport layer Protocol ICMP");
					  return;
					  }
			case IPPROTO_IP: {//printf("\nTransport layer Protocol IP");
					  return;
					 }
			default : {//printf("\nUnKOWN Protocol");
				  return;	
				  }
		}

		tcp=(struct sniff_tcp *)(packet+SIZE_ETHERNET+ip_sz);
		trans_sz = TH_OFF(tcp)*4;

		if(trans_sz<20)
		{
//			printf("\nError tcp header less than 20 bytes . . .");
			return;
		}
	
		printf("\n------------------\n-%d Packet captured\n----------------\n SOURCE IP ADDRESS :: %s.",(cnt+1),inet_ntoa(ip->ip_src));
		cnt++;

//		printf("Source ip :: %s ",inet_ntoa(ip->ip_src));
//		printf("Destination :: %s",inet_ntoa(ip->ip_dst));
		
		payload_sz = ntohs(ip->ip_len) - (ip_sz + trans_sz);

		if(payload_sz<8 || payload_sz > 190)
		{
			return;
		}

		payload=(u_char *)(packet+SIZE_ETHERNET+ip_sz+trans_sz);

		char temp_payload_print[200];
		for(int i=0;i<payload_sz;i++)
		{
			temp_payload_print[i]=payload[i];
		}
		temp_payload_print[payload_sz]='\0';
		printf("\nPayload :: %s  \n Payload divided in to #%d Substrings \n",temp_payload_print , (payload_sz-beta_sz));
//		printf("\npayload size :: %d",payload_sz);

		for(j=0;j<(payload_sz-beta_sz+1);j++)
		{
			char substring[(beta_sz+1)];
			memset(substring,'\0',(beta_sz+1));
                        //printf("Sizeof Sub string : %sand betasize : %d",substring,beta_sz);
		//	unsigned char *substring=(unsigned char *)kmalloc(beta,GFP_KERNEL);
			memcpy(substring,(payload+j),beta_sz);
		//	substring[beta]='\0';
		//	substring=(unsigned char *)"12345678";
			//memset((substring+beta_sz),'\0',1);
                        //printf("Substring Called: %s Size: %d\n  ", substring , strlen(substring));
			detect_it(substring,inet_ntoa(ip->ip_src));
		}
	}
}

void init_tables()
{
	for(int i=0;i<65500;i++)
	{
		prvl_table[i].valid=0;
		
		adisp_table[i].valid=0;
	}
}

int main(int agrc, char *argv[])
{
	char *dev=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle=NULL;
	//bpf_u_int32 net;
	//bpf_u_int32 mask;

	dev=pcap_lookupdev(errbuf);
	if(dev==NULL)
	{
		printf("\nError in finding device :: %s",errbuf);
		exit(EXIT_FAILURE);		
	}		
	
	printf("\nCapturing packet on device %s . . .",dev);

	if((pcap_lookupnet(dev,&net,&mask,errbuf)==-1))
	{
		printf("\nError getting net mask of device :: %s. %s",dev,errbuf);
		net=0;
		mask=0;
		exit(EXIT_FAILURE);
	}

	struct in_address *tmp,*tmp1;
	tmp=(struct in_address *)&net;
	tmp1=(struct in_address *)&mask;

	printf("\nNet Address :: %d.%d.%d.%d",tmp->one,tmp->two,tmp->three,tmp->four);
	printf("    Mask :: %d.%d.%d.%d",tmp1->one,tmp1->two,tmp1->three,tmp1->four);

	handle=pcap_open_live(dev,SNAP_LEN,1,1000,errbuf);
	if(handle==NULL)
	{
		printf("Error opening device %s . . . %s",dev,errbuf);	
		exit(EXIT_FAILURE);
	}

	printf("\nDevice %s opened for sniffing . . .",dev);

	init_tables();

	pcap_loop(handle,-1,worm_detect_func,NULL);

	pcap_close(handle);

	printf("\nPacket capture closed . . .");

	return 0;	
}
