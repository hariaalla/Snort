/* $Id$ */
/* Snort Detection Plugin Source File Template */

/* sp_template
 *
 * Purpose:
 *
 * Detection engine plugins test an aspect of the current packet and report
 * their findings.  The function may be called many times per packet with
 * different arguments.  These functions are acccessed from the rules file
 * as standard rule options.  When adding a plugin to the system, be sure to
 * add the "Setup" function to the InitPlugins() function call in
 * plugbase.c!
 *
 * Arguments:
 *
 * This is the type of arguements that the detection plugin can take when
 * referenced as a rule option
 *
 * Effect:
 *
 * What the plugin does.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#include <sys/types.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "sp_ip_id_check.h"
#include "sf_snort_packet.h"
#include "spp_exist_ipid.h"

/*
 * don't forget to include the name of this file in plugbase.c!
 */

/*
 * setup any data structs here
 */

typedef struct _ExistIpIdData
{
/*
     * your detection option data
     * structure info goes here
     */
   /* Packet *p;*/
    Packet Idle_Scan_Attack_Packet_Array[100000];

} ExistIpIdData;

/* function prototypes go here */
static void ExistIpIdInit(char *, OptTreeNode *, int);
static void ExistIpIdRuleParseFunction(char *, OptTreeNode *, ExistIpIdData *);
static int ExistIpIdDetectorFunction(Packet *, struct _OptTreeNode *,
        OptFpList *);

/*
 *
 * Function: SetupTemplate()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupExistIpId()
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("exist-ipid", ExistIpIdInit);

    DebugWrap(DebugMessage(DEBUG_PLUGIN,"Plugin: ExistIpId Setup\n"););
}



/*
 *
 * Function: TemplateInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 */
static void ExistIpIdInit(char *data, OptTreeNode *otn, int protocol)/*might need to include struct _SnortConfig *sc*/
{
    OptFpList *ofl;
    ExistIpIdData *existIpId_data;


    /*
     * allocate the data structure and attach
     * it to the rule's data struct list
     */
    existIpId_data = (ExistIpIdData *) SnortAlloc(sizeof(ExistIpIdData));

    if(existIpId_data == NULL)
    {
        FatalError("%s (%d) : Unable to allocate existIpId_data node\n", file_name, file_line);
    }

    /*
     * If this is a transport layer protocol plugin, be sure to
     * check that the protocol that is passed in matches the
     * transport layer protocol that you're using for this rule!
     */

    /*
     * any other initialization of this plugin should be performed here
     */

    /*
     * this is where the keyword arguments are processed and
     * placed into the rule option's data structure
     */
    ExistIpIdRuleParseFunction(data, otn, existIpId_data);

    /*
     * finally, attach the option's detection function
     * to the rule's detect function pointer list
     *
     * AddOptFuncToList returns a pointer to the node in
     * the function pointer list where the detector function
     * is linked into the detection engine, we will grab the
     * pointer to this node so that we can assign the
     * config data for this rule option to the functional
     * node's context pointer*/

    ofl = AddOptFuncToList(ExistIpIdDetectorFunction, otn);

    /*
     * this is where we set the functional node's context pointer
     * so that the plugin can find the data to test the network
     * traffic against*/

    ofl->context = (void *) existIpId_data;
}



/*
 *
 * Function: TemplateRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *            td => pointer to the configuration storage struct
 *
 * Returns: void function
 *
 */
static void ExistIpIdRuleParseFunction(
        char *data,
        OptTreeNode *otn,
        ExistIpIdData *ed)
{
    /*
     * manipulate the option arguments here*/

     errno = 0;
     ed->significant_Packet_Array = (u_int16) strtol(data, (char **)NULL, 10);

     if(errno)
     {
         FatalError("%s (%d) : invalid spa value : %s\n", file_name, file_line, data) ;
     }
     DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Significant Packet Array set to %d\n", ed->significant_Packet_Array););

   

}


/*
 *
 * Function: TemplateDetectorFunction(char *, OptTreeNode *, OptFpList *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *            fp_list => pointer to the function pointer list current node
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list
 *
 */
static int ExistIpIdDetectorFunction(
        Packet *p,
        struct _OptTreeNode *otn,
        OptFpList *fp_list)
{
    ExistIpIdData *ed;   /* ptr to the detection option's data */

    /*
     * Try to make this function as quick as possible, the faster the
     * detection plugins are, the less packet loss the program will
     * experience!  Avoid doing things like declaring variables or
     * anything other than just doing the test and moving on...
     */

    /*
     * get the current option's context data*/

    ed = (ExistIpIdData *) fp_list->context;

    /*
     * your detection function tests go here*/

    if (p->tcp_header)
    {
        /* call the next function in the function list recursively */
        /* THIS CALL *MUST* BE IN THE PLUGIN, OTHERWISE YOU WILL BREAK
           SNORT'S DETECTION ENGINE!!!*/
        int i=0; int j=0;
        int pkt_Dst_Ip[100000];
        Packet k; int q=0; int r=0;
        
        int pkt_Ip_Id = NULL;
        while(Significant_Packet_Array[i]!=0)
        {
            k=Significant_Packet_Array[i];
            if(flag(k)==SYN)
            {
                pkt_Dst_Ip[j]=GET_DST_IP(k);
                pkt_Ip_Id=GET_IPH_ID(k);
                i++;
                j++;
            }
            else
            {
                if((flag(k)==RST) and (pkt_Dst_Ip.Length!=0))
                {
                    if((pkt_Dst_Ip.Contains(GET_DST_IP(k)) && (GET_IPH_ID(k)==Pkt_Ip_Id+2))
                    {
                        ed->Idle_Scan_Packet_Array[r]=k;
                        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Idle scan detected!\n"););
                        r++;
                        i++;
                    }
                    else
                    {
                        i++;
                    }
                else
                {
                    i++;
                }

                }
            }
        }

        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        

        DebugMessage(DEBUG_PLUGIN,"No match\n");
    }
#endif

    /*
     * if the test isn't successful, this function *must* return 0*/

    return 0;
}
