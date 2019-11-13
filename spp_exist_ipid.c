/* $Id$ */
/* Snort Preprocessor Plugin Source File Template */

/* spp_template
 *
 * Purpose:
 *
 * Preprocessors perform some function *once* for *each* packet.  This is
 * different from detection plugins, which are accessed depending on the
 * standard rules.  When adding a plugin to the system, be sure to
 * add the "Setup" function to the InitPreprocessors() function call in
 * plugbase.c!
 *
 * Arguments:
 *
 * This is the list of arguements that the plugin can take at the
 * "preprocessor" line in the rules file
 *
 * Effect:
 *
 * What the preprocessor does.  Check out some of the default ones
 * (e.g. spp_frag2) for a good example of this description.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>

/*
 * If you're going to issue any alerts from this preproc you
 * should include generators.h and event_wrapper.h
 */
#include "generators.h"
#include "event_wrapper.h"

#include "util.h"
#include "plugbase.h"
#include "parser.h"


/*
 * put in other inculdes as necessary
 */

/*
 * your preprocessor header file goes here if necessary, don't forget
 * to include the header file in plugbase.h too!
 */
#include "spp_existipid.h"

/*
 * define any needed data structs for things like configuration
 */
/*
 * define any needed data structs for things like configuration
 */
typedef struct _ExistIpIdData
{
    /* Your struct members here */
    Packet Significant_Packet_Array[1000000];

} ExistIpIdData;



static void PreprocFunction(Packet *);


void SetupIpId()
{
    /*
     * link the preprocessor keyword to the init function in
     * the preproc list
     */
    RegisterPreprocessor("exist-ipid", ExistIpIdInit);

    DebugWrap(DebugMessage(DEBUG_PLUGIN,"Preprocessor: ExistIpId is setup...\n"););
}


/*
 * Function: TemplateInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void ExistIpIdInit(u_char *args)
{
    RegisterPreprocessor("exist-ipid", ExistIpIdInit);
    DebugWrap(DebugMessage(DEBUG_PLUGIN,"Preprocessor: ExistIpId Initialized\n"););

    /*
     * parse the argument list from the rules file
     */
    ParseExistIpIdArgs(args);

    AddFuncToPreprocList(PreprocFunction);

}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct
 *
 * Returns: void function
 *
 */
static void PreprocFunction(Packet *p)
{

    /* your preproc function goes here.... */

    /*
     * if you need to issue an alert from your preprocessor, check out
     * event_wrapper.h, there are some useful helper functions there
     */
     int i=0;
     while(p[i].data != NULL)
    {   
        if(IsTCP(p)){
            if(flag(p)==SYN or flag(p)==RST){
                if(GET_IPH_ID(p)!=NULL){
                        Significant_Packet_Array[i]=p;
                        i++;
                }
                else{
                    i++;
                }
            }
            else{
                i++;
            }
        }
        else{
            i++;
        }
     }

}

