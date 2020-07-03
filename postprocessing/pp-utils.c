#include "pp-utils.h"

void init_dimension_array(dimension_array *arr, size_t initialSize) {
	arr->array = (struct dimension_item *)malloc(initialSize * sizeof(struct dimension_item));
	arr->used = 0;
	arr->size = initialSize;
}

void insert_dimension_array(dimension_array *arr, dimension_item element) {
	if (arr->used == arr->size) {
		arr->size *= 2;
		arr->array = (struct dimension_item *)realloc(arr->array, arr->size * sizeof(struct dimension_item));
	}
	arr->array[arr->used++] = element;
}

void free_dimension_array(dimension_array *arr) {
	free(arr->array);
	arr->array = NULL;
	arr->used = arr->size = 0;
}

dimension_item get_optimal_dimensions(dimension_item arr[], int len, int threshold) {
	dimension_item dimensions;
	dimensions.width = arr[0].width;
	dimensions.height = arr[0].height;

	int i;
	for (i = 0; i < len; i++) {
		int prev = arr[i].seq - arr[i - 1].seq;
		int next = arr[i + 1].seq - arr[i].seq;
		if (prev >= threshold && next >= threshold) {
			if (arr[i].width > dimensions.width)
				dimensions.width = arr[i].width;
			if (arr[i].height > dimensions.height)
				dimensions.height = arr[i].height;
		}
	}

	return dimensions;
}