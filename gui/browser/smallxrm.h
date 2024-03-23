/*
  Small XRM (X Resource Manager) in C.
  Public domain.
*/

#ifndef SMALLXRM_H_INCLUDED
#define SMALLXRM_H_INCLUDED

typedef struct xrm_db xrm_db; // type of database nodes
typedef unsigned int xrm_quark; // type of quarks

#define xrm_nullq ((xrm_quark)0) // not a valid quark
#define xrm_anyq ((xrm_quark)1) // the "?" quark

// Memory handling: Any xrm_db* values returned by these functions are
// invalid if xrm_destroy() is subsequently used on that node or on any of
// its ancestor nodes. Any string pointers returned by these functions are
// invalid if the node it belongs to is destroyed, if the resource value is
// changed, or if xrm_annihilate() is called. Do not free them by yourself.

void xrm_annihilate(void);
// Releases all memory used by this library. Does nothing if not
// initialized. You must first call xrm_destroy() on any existing resource
// databases you may have allocated. After xrm_annihilate() is called,
// nothing else should be called without calling xrm_init() first. You may
// safely terminate the program without calling this function, since the
// only thing it does is free memory, which is automatically done when the
// program terminates anyways.

xrm_db*xrm_create(void);
// Creates a new empty resource database.

void xrm_destroy(xrm_db*db);
// Destroy an existing resource database. All sub-databases are also
// destroyed. The memory is freed.

void*xrm_enumerate(xrm_db*db,void*(*cb)(xrm_db*,void*,int,xrm_quark),void*usr);
// Calls the given callback function for each child node of the resource
// database; the first two arguments are the same as db and usr given to
// this function, while the next is 1 if loose or 0 if tight, and the next
// is the quark that is in use. You can then call xrm_sub() in order to
// access the sub-database it contains. If the callback returns null, then
// the enumeration continues, otherwise it returns with the same value. It
// only goes one level deep; you can use it recursively to go more deep.

const char*xrm_get(xrm_db*db);
// Retrieves the value of the resource at the root of the given database.
// If there is no value, the result is a null pointer.

const char*xrm_get_resource(xrm_db*db,const xrm_quark*ns,const xrm_quark*cs,int len);
// Retrieves the value of a given resource, given the root node, list of
// quarks for the name of the query, list of quarks for the class of the
// query, and the length of the name and class list. Both list pointers
// must be non-null, but you may give the same pointers for each. If there
// is no such resource, the result is a null pointer.

int xrm_init(void*(*f)(void*,size_t));
// Initialize the library; must be called exactly once, before anything
// else is called. The argument should be realloc, or your own function
// that does the same thing; all dynamic memory allocation done by the
// library will use the function you give for this purpose. Return value
// is 0 if success or -1 if error.

int xrm_init_quarks(const char*const*list);
// Optional. If you call it, it must be called after xrm_init() is called
// before any other library functions are called. The argument is a null
// terminated list of strings, all of which must be unique, and none of
// them may be "?". They are assigned constant quark numbers, where the
// first string is the name of quark number 2, the next being quark number
// 3, and so on. You can use this in order to make compile-time constants
// for the quarks used in your program. The library does not make copies
// of the strings; they must exist for the entire duration of the library.
// The return value is 0 if OK or -1 if not OK.

int xrm_link(xrm_db*db,int loose,xrm_quark q,xrm_db*ins);
// Insert a node (the fourth argument) as child of the node given by the
// first argument. The node is now "owned" by the parent; if you then call
// xrm_destroy() without unlinking it, it will destroy that one too. You
// normally do not need to use this function. Return value is 0 if it is
// successful or -1 in case of error.

int xrm_load(xrm_db*db,FILE*fp,int o);
// Load a resource database from an open file handle. #include is not
// currently implemented. It loads into the given database, and returns 0
// if successful or -1 if error. The third argument is nonzero if it
// should override existing resources, or zero if it doesn't.

int xrm_load_line(xrm_db*db,const char*s,int o);
// Load a resource from a string, which must be a single line; in case of
// any line breaks, they and anything after them are ignored. Line
// continuation is not implemented by xrm_load_line() (but xrm_load() does
// implement it).

xrm_quark xrm_make_quark(const char*name,int addnew);
// Make a new quark (or retrieves an existing quark by name) and returns
// it. The return value is zero (xrm_nullq) if it does not exist. The
// second argument is zero to retrieve only existing quarks, or nonzero if
// it should make a new quark if there isn't an existing quark with the
// given name. If the first argument is null and the second argument is
// nonzero, then it makes a new unique quark. The library makes a copy of
// the passed string if a new quark is made; you need not copy it yourself.

int xrm_merge(xrm_db*to,xrm_db*from,int o);
// Merge the second database into the first one. Returns 0 if success or
// -1 if error. The third argument is zero if the existing resources have
// priority or nonzero if the new ones do.

const char*xrm_name(xrm_quark n);
// Returns the name of the given quark. If there is no such quark, or if
// it is xrm_nullq, or if it has no name, the result is null.

int xrm_put(xrm_db*db,const char*v,int o);
// Set the value of the node. First argument is the node, second argument
// is the value (the library makes a copy of it) or null to delete the
// value, and third argument is nonzero to override an existing value or
// zero to not change an existing value. Returns 0 if successful.

int xrm_put_resource(xrm_db*db,const xrm_quark*q,const char*b,const char*v,int o);
// Set the value of a resource. The second argument is the quark list, the
// third argument is the binding list, the fourth argument is the value,
// and the fifth argument specifies to override or not. The binding list
// is a string containing characters '*' and '.' and must have the same
// length as the quark list.

void*xrm_search(xrm_db*db,const xrm_quark*ns,const xrm_quark*cs,int len,void*(*cb)(xrm_db*,void*),void*usr);
// Perform a search of the given resource database, given the list of
// quarks for name of the query, quarks for class of the query, length of
// the quark lists, a callback function, and the user value for the
// callback function. Both the name and class list must be not null, but
// they may be the same pointer. It calls the callback function for each
// node in priority order, and stops once the callback function returns
// not null, and then xrm_search() returns the same value.

xrm_db*xrm_sub(xrm_db*db,int loose,xrm_quark q);
// Access a child node of the given node. The second argument is zero for
// a tight binding or nonzero for loose. The third is the quark. If no
// such node exists, a new node with no value or children is created.

#endif

