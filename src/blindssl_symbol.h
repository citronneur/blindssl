#ifndef __BLINDSSL_SYMBOL__
#define __BLINDSSL_SYMBOL__

/*!
 *  \brief  loop on symbol in the file by parsing the ELF
 *  \param  path    path to the elf module
 *  \param  symname name of the symbol
 *  \return -1 if not found or offset of the symbol
 */
int blindssl_find_symbol_address(const char *path, const char* symname);

#endif