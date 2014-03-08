/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcp.h"
#include "util.h"
#include "nids.h"

void
nids_no_mem(char *func)
{
  fprintf(stderr, "Out of memory in %s.\n", func);
  exit(1);
}


// 以字节为单位，分配内存
char *
test_malloc(int x)
{

  char *ret = malloc(x);
  

  if (!ret)
    nids_params.no_mem("test_malloc");



  return ret;
}

// 纯粹的单向链表查找并添加
void
register_callback(struct proc_node **procs, void (*x))
{
  struct proc_node *ipp;

  // 找到最后一个节点，如果中途遇到相同的函数，说明已经注册过了，立即返回
  for (ipp = *procs; ipp; ipp = ipp->next)
    if (x == ipp->item)
      return;


  // 否则申请一个节点，然后加到链表头
  ipp = mknew(struct proc_node);
  ipp->item = x;
  ipp->next = *procs;
  *procs = ipp;

}


// 纯粹的单向链表删除
void
unregister_callback(struct proc_node **procs, void (*x))
{
  struct proc_node *ipp;
  struct proc_node *ipp_prev = 0;

  for (ipp = *procs; ipp; ipp = ipp->next) {
  	// 如果相等，那么就把当前节点摘下来
    if (x == ipp->item) {
      if (ipp_prev)
	ipp_prev->next = ipp->next;
      else
	*procs = ipp->next;
      free(ipp);
      return;
    }
    ipp_prev = ipp;
  }
}
