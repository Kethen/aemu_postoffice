#include "list.h"
#include "log_impl.h"

#include <stdlib.h>
#include <stdio.h>

int main(){
	void *data[] = {(void *)0x1, (void *)0x2, (void *)0x3};

	// push_back & pop_back
	void *list = init_list();
	list_push_back(list, data[0]);
	list_push_back(list, data[1]);
	list_push_back(list, data[2]);

	if (list_get_front(list) != data[0]){
		printf("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != data[2]){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 3){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	void *itr = list_begin_itr(list);
	for (int i = 0;i < 3;i++){
		if (itr == NULL){
			LOG("%s,%d: list ended unexpectedly\n", __func__, __LINE__);
			exit(1);
		}
		if (list_itr_get_data(itr) != data[i]){
			LOG("%s,%d: bad data from list itr\n", __func__, __LINE__);
			exit(1);
		}
		itr = list_itr_next(itr);
	}
	if (itr != NULL){
		LOG("%s,%d: itr is not null\n", __func__, __LINE__);
		exit(1);
	}

	for (int i = 0;i < 3;i++){
		if (list_get_front(list) != data[0]){
			LOG("%s,%d: bad front data %p\n", __func__, __LINE__, list_get_front(list));
			exit(1);
		}
		if (list_get_back(list) != data[2 - i]){
			LOG("%s,%d: bad back data %p\n", __func__, __LINE__, list_get_back(list));
			exit(1);
		}
		if (list_get_size(list) != 3 - i){
			LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
			exit(1);
		}
		list_pop_back(list);
	}
	if (list_get_front(list) != NULL){
		LOG("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != NULL){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 0){
		LOG("%s, %d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	// push_front & pop_front
	list_push_front(list, data[0]);
	list_push_front(list, data[1]);
	list_push_front(list, data[2]);

	if (list_get_front(list) != data[2]){
		LOG("%s,%d: bad front data %p\n", __func__, __LINE__, list_get_front(list));
		exit(1);
	}
	if (list_get_back(list) != data[0]){
		LOG("%s,%d: bad back data %p\n", __func__, __LINE__, list_get_back(list));
		exit(1);
	}
	if (list_get_size(list) != 3){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	itr = list_begin_itr(list);
	for (int i = 0;i < 3;i++){
		if (itr == NULL){
			LOG("%s,%d: list ended unexpectedly\n", __func__, __LINE__);
			exit(1);
		}
		if (list_itr_get_data(itr) != data[2 - i]){
			LOG("%s,%d: bad data from list itr\n", __func__, __LINE__);
			exit(1);
		}
		itr = list_itr_next(itr);
	}
	if (itr != NULL){
		LOG("%s,%d: itr is not null\n", __func__, __LINE__);
		exit(1);
	}

	for (int i = 0;i < 3;i++){
		if (list_get_front(list) != data[2 - i]){
			LOG("%s,%d: bad front data %p\n", __func__, __LINE__, list_get_front(list));
			exit(1);
		}
		if (list_get_back(list) != data[0]){
			LOG("%s,%d: bad back data %p\n", __func__, __LINE__, list_get_back(list));
			exit(1);
		}
		if (list_get_size(list) != 3 - i){
			LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
			exit(1);
		}
		list_pop_front(list);
	}
	if (list_get_front(list) != NULL){
		LOG("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != NULL){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 0){
		LOG("%s, %d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	// remove
	list_push_back(list, data[0]);
	list_push_back(list, data[1]);
	list_push_back(list, data[2]);

	itr = list_begin_itr(list);
	itr = list_itr_next(itr);
	list_remove(list, itr);

	if (list_get_front(list) != data[0]){
		printf("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != data[2]){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 2){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	list_push_back(list, data[1]);
	itr = list_begin_itr(list);
	list_remove(list, itr);

	if (list_get_front(list) != data[2]){
		printf("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != data[1]){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 2){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	list_push_back(list, data[0]);
	itr = list_begin_itr(list);
	itr = list_itr_next(itr);
	itr = list_itr_next(itr);
	list_remove(list, itr);

	if (list_get_front(list) != data[2]){
		printf("%s,%d: bad front data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_back(list) != data[1]){
		LOG("%s,%d: bad back data\n", __func__, __LINE__);
		exit(1);
	}
	if (list_get_size(list) != 2){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	itr = list_begin_itr(list);
	list_remove(list, itr);
	itr = list_begin_itr(list);
	list_remove(list, itr);

	if (list_get_size(list) != 0){
		LOG("%s,%d: bad list size %d\n", __func__, __LINE__, list_get_size(list));
		exit(1);
	}

	free_list(list);
}
