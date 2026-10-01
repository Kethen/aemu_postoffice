#ifndef __LIST_H
#define __LIST_H

#include <stdbool.h>

void *init_list();
// all nodes are freed, make sure you have already already cleaned up the data pointed to by the list
void free_list(void *list_handle);

// malloc is called on the new node, data is not copied, only the pointer is saved
bool list_push_front(void *list_handle, void *data);
bool list_push_back(void *list_handle, void *data);

// free is called only on the list node, make sure you have already already cleaned up the data pointed to by the list
void list_pop_front(void *list_handle);
void list_pop_back(void *list_handle);

// getting the data pointer back
void *list_get_front(void *list_handle);
void *list_get_back(void *list_handle);

int list_get_size(void *list_handle);

void *list_begin_itr(void *list_handle);
void *list_itr_next(void *list_itr);
void *list_itr_get_data(void *list_itr);

#endif
