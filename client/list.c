#include <stdlib.h>

#include "list.h"
#include "log_impl.h"

struct list{
	struct list_node *begin;
	struct list_node *end;
	int size;
};

struct list_node{
	struct list_node *next;
	struct list_node *last;
	void *data;
};

void *init_list(){
	struct list *new_list = (struct list *)malloc(sizeof(struct list));
	if (new_list == NULL){
		LOG("%s: out of memory while allocating list\n", __func__);
		return NULL;
	}
	new_list->begin = NULL;
	new_list->end = NULL;
	new_list->size = 0;
	return new_list;
}

static struct list_node *allocate_list_node(void *data){
	struct list_node *new_node = (struct list_node *)malloc(sizeof(struct list_node));
	if (new_node == NULL){
		LOG("%s: out of memory while allocating list node\n", __func__);
		return NULL;
	}

	new_node->next = NULL;
	new_node->last = NULL;
	new_node->data = data;

	return new_node;
}

bool list_push_front(void *list_handle, void *data){
	struct list *list = (struct list *)list_handle;
	struct list_node *new_node = allocate_list_node(data);
	if (new_node == NULL){
		return false;
	}

	list->size++;

	if (list->begin == NULL){
		list->begin = new_node;
		list->end = new_node;
		return true;
	}

	new_node->next = list->begin;
	list->begin->last = new_node;
	list->begin = new_node;
	return true;
}

bool list_push_back(void *list_handle, void *data){
	struct list *list = (struct list *)list_handle;
	struct list_node *new_node = allocate_list_node(data);
	if (new_node == NULL){
		return false;
	}

	list->size++;

	if (list->end == NULL){
		list->begin = new_node;
		list->end = new_node;
		return true;
	}

	list->end->next = new_node;
	new_node->last = list->end;
	list->end = new_node;
	return true;
}

void list_pop_front(void *list_handle){
	struct list *list = (struct list *)list_handle;
	struct list_node *begin_node = list->begin;
	if (begin_node == NULL){
		LOG("%s: trying to pop front while list is empty...\n", __func__);
		return;
	}

	if (begin_node->next != NULL){
		begin_node->next->last = NULL;
	} else {
		list->end = NULL;
	}

	list->begin = begin_node->next;
	free(begin_node);
	list->size--;
}

void list_pop_back(void *list_handle){
	struct list *list = (struct list *)list_handle;
	struct list_node *end_node = list->end;
	if (end_node == NULL){
		LOG("%s: trying to pop back while list is empty...\n", __func__);
		return;
	}

	if (end_node->last != NULL){
		end_node->last->next = end_node->next;
	} else {
		list->begin = NULL;
	}

	list->end = end_node->last;
	free(end_node);
	list->size--;
}

void *list_get_front(void *list_handle){
	struct list *list = (struct list *)list_handle;
	if (list->begin == NULL){
		return NULL;
	}
	return list->begin->data;
}

void *list_get_back(void *list_handle){
	struct list *list = (struct list *)list_handle;
	if (list->end == NULL){
		return NULL;
	}
	return list->end->data;
}

int list_get_size(void *list_handle){
	struct list *list = (struct list *)list_handle;
	return list->size;
}

void free_list(void *list_handle){
	struct list *list = (struct list *)list_handle;
	while(list->size != 0){
		list_pop_front(list_handle);
	}
	free(list);
}

void *list_begin_itr(void *list_handle){
	struct list *list = (struct list *)list_handle;
	return list->begin;
}

void *list_itr_next(void *list_itr){
	struct list_node *list_node = (struct list_node*)list_itr;
	return list_node->next;
}
void *list_itr_get_data(void *list_itr){
	struct list_node *list_node = (struct list_node*)list_itr;
	return list_node->data;
}

void list_remove(void *list_handle, void *list_itr){
	struct list *list = (struct list *)list_handle;
	struct list_node *list_node = (struct list_node*)list_itr;
	if (list->size == 0){
		LOG("%s: trying to remove node on an empty list...\n", __func__);
		return;
	}

	if (list_node->last == NULL){
		list->begin = list_node->next;
	} else {
		list_node->last->next = list_node->next;
	}

	if (list_node->next == NULL){
		list->end = list_node->last;
	} else {
		list_node->next->last = list_node->last;
	}

	free(list_node);
	list->size--;
}
