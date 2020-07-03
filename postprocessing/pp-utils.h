#include <stdio.h>
#include <stdlib.h>

typedef struct dimension_item {
	int width;
	int height;
	int seq;
} dimension_item;

typedef struct dimension_array {
	dimension_item *array;
	size_t used;
	size_t size;
} dimension_array;

void init_dimension_array(dimension_array *arr, size_t initialSize);
void insert_dimension_array(dimension_array *arr, dimension_item element);
void free_dimension_array(dimension_array *arr);
dimension_item get_optimal_dimensions(dimension_item arr[], int len, int threshold);
