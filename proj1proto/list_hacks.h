#ifndef LIST_HACKS_H
#define LIST_HACKS_H
#if !defined(__KERNEL__)
#include <stddef.h>
 /**
  * Casts a member of a structure out to the containing structure
  * @param ptr        the pointer to the member.
  * @param type       the type of the container struct this is embedded in.
  * @param member     the name of the member within the struct.
  *
  */
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

# define POISON_POINTER_DELTA 0
  /*
   * These are non-NULL pointers that will result in page faults
   * under normal circumstances, used to verify that nobody uses
   * non-initialized list entries.
   */
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x200 + POISON_POINTER_DELTA)

   /*
    * WRITE_ONCE and READ_ONCE do NOT provide their Kernel utility
    * and are not in any way, shape or form equivalent to their kernel
    * implementations. Do NOT use this file with the linux kernel
    */
#define WRITE_ONCE(x, val) x = (val)

#define READ_ONCE(x) x

struct list_head {
    struct list_head *next, *prev;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

struct hlist_head {
    struct hlist_node *first;
};

typedef _Bool  bool;

enum {
    false = 0,
    true = 1
};
#endif // __KERNEL__
#endif //LIST_HACKS_H