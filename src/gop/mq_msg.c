/*
   Copyright 2016 Vanderbilt University

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//*************************************************************
//  Routines to provide frame support for MQ layer
//*************************************************************

#include "mq_portal.h"
#include <tbx/type_malloc.h>
#include <tbx/log.h>
#include <stdlib.h>

//**************************************************************
//  mq_get_frame - Returns the frame data
//**************************************************************

int mq_get_frame(mq_frame_t *f, void **data, int *size)
{
    if (f == NULL) {
        *data = NULL;
        *size = 0;
        return(0);
    }

    *size = f->len;
    *data = f->data;

    return(f->auto_free);
}

//*************************************************************
//  mq_frame_strdup - Converts the contents ofthe frame to a NULL
//    terminated string and returns the pointer.  The
//    caller is responsible for freeing the data.
//*************************************************************

char *mq_frame_strdup(mq_frame_t *f)
{
    char *data, *str;
    int n;

    mq_get_frame(f, (void **)&data, &n);

    if (data == NULL) return(NULL);

    tbx_type_malloc(str, char, n+1);
    str[n] = 0;
    memcpy(str, data, n);

    return(str);
}

//*************************************************************
// quick stack related msg routines
//*************************************************************

mq_msg_t *mq_msg_new()
{
    return(tbx_stack_new());
}
mq_frame_t *mq_msg_first(mq_msg_t *msg)
{
    tbx_stack_move_to_top(msg);
    return((mq_frame_t *)tbx_stack_get_current_data(msg));
}
mq_frame_t *mq_msg_last(mq_msg_t *msg)
{
    tbx_stack_move_to_bottom(msg);
    return((mq_frame_t *)tbx_stack_get_current_data(msg));
}
mq_frame_t *mq_msg_next(mq_msg_t *msg)
{
    tbx_stack_move_down(msg);
    return((mq_frame_t *)tbx_stack_get_current_data(msg));
}
mq_frame_t *mq_msg_prev(mq_msg_t *msg)
{
    tbx_stack_move_up(msg);
    return((mq_frame_t *)tbx_stack_get_current_data(msg));
}
mq_frame_t *mq_msg_current(mq_msg_t *msg)
{
    return((mq_frame_t *)tbx_stack_get_current_data(msg));
}
mq_frame_t *mq_msg_pluck(mq_msg_t *msg, int move_up)
{
    mq_frame_t *f = tbx_stack_get_current_data(msg);
    tbx_stack_delete_current(msg, move_up, 0);
    return(f);
}
void mq_msg_tbx_stack_insert_above(mq_msg_t *msg, mq_frame_t *f)
{
    tbx_stack_insert_above(msg, f);
}
void mq_msg_tbx_stack_insert_below(mq_msg_t *msg, mq_frame_t *f)
{
    tbx_stack_insert_below(msg, f);
}
void mq_msg_push_frame(mq_msg_t *msg, mq_frame_t *f)
{
    tbx_stack_push(msg, f);
}
void mq_msg_append_frame(mq_msg_t *msg, mq_frame_t *f)
{
    tbx_stack_move_to_bottom(msg);
    tbx_stack_insert_below(msg, f);
}

void mq_frame_set(mq_frame_t *f, void *data, int len, int auto_free)
{
    f->data = data;
    f->len = len;
    f->auto_free = auto_free;
}

mq_frame_t *mq_frame_new(void *data, int len, int auto_free)
{
    mq_frame_t *f;

    tbx_type_malloc(f, mq_frame_t, 1);
    mq_frame_set(f, data, len, auto_free);

    return(f);
}

mq_frame_t *mq_frame_dup(mq_frame_t *f)
{
    void *data, *copy;
    int size;

    mq_get_frame(f, &data, &size);
    if (size == 0) {
        copy = NULL;
    } else {
        tbx_type_malloc(copy, void, size);
        memcpy(copy, data, size);
    }

    return(mq_frame_new(copy, size, MQF_MSG_AUTO_FREE));
}

void mq_frame_destroy(mq_frame_t *f)
{
    if ((f->auto_free == MQF_MSG_AUTO_FREE) && (f->data)) {
        free(f->data);
    } else if (f->auto_free == MQF_MSG_INTERNAL_FREE) {
        zmq_msg_close(&(f->zmsg));
    }
    free(f);
}

void mq_msg_destroy(mq_msg_t *msg)
{
    mq_frame_t *f;

    while ((f = tbx_stack_pop(msg)) != NULL) {
        mq_frame_destroy(f);
    }

    tbx_stack_free(msg, 0);
}

void mq_msg_push_mem(mq_msg_t *msg, void *data, int len, int auto_free)
{
    tbx_stack_push(msg, mq_frame_new(data, len, auto_free));
}
void mq_msg_append_mem(mq_msg_t *msg, void *data, int len, int auto_free)
{
    tbx_stack_move_to_bottom(msg);
    tbx_stack_insert_below(msg, mq_frame_new(data, len, auto_free));
}

void mq_msg_append_msg(mq_msg_t *msg, mq_msg_t *extra, int mode)
{
    tbx_stack_ele_t *curr;
    mq_frame_t *f;
    char *data;

    tbx_stack_move_to_top(msg);
    for (curr = tbx_stack_get_top(msg); 
            curr != NULL;
            curr = tbx_stack_ele_get_down(curr)) {
        f = (mq_frame_t *)tbx_stack_ele_get_data(curr);
        if (mode == MQF_MSG_AUTO_FREE) {
            tbx_type_malloc(data, char, f->len);
            memcpy(data, f->data, f->len);
            tbx_stack_insert_below(msg, mq_frame_new(data, f->len, MQF_MSG_AUTO_FREE));
        } else {
            tbx_stack_insert_below(msg, mq_frame_new(f->data, f->len, MQF_MSG_KEEP_DATA));
        }
    }
}

mq_msg_hash_t mq_msg_hash(mq_msg_t *msg)
{
    tbx_stack_ele_t *curr;
    mq_frame_t *f;
    unsigned char *data;
    unsigned char *p;
    mq_msg_hash_t h;
    int size, n;

    n = 0;
    h.full_hash = h.even_hash = 0;
    for (curr = tbx_stack_get_top(msg); 
            curr != NULL;
            curr = tbx_stack_ele_get_down(curr)) {
        f = (mq_frame_t *)tbx_stack_ele_get_data(curr);
        mq_get_frame(f, (void **)&data, &size);
        for (p = data; size > 0; p++, size--) {
            h.full_hash = h.full_hash * 33 + *p;
            if ((n%2) == 0) h.even_hash = h.even_hash * 33 + *p;

            n++;
        }
    }

    return(h);
}

//*************************************************************
// mq_msg_total_size - Total size of mesg
//*************************************************************

int mq_msg_total_size(mq_msg_t *msg)
{
    mq_frame_t *f;
    int n;

    n = 0;
    tbx_stack_move_to_top(msg);
    while ((f = tbx_stack_get_current_data(msg)) != NULL) {
        n += f->len;
        tbx_stack_move_down(msg);
    }

    return(n);
}
