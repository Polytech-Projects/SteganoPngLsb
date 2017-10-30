/**
 * Pour compiler: gcc main.c -lssl -lcrypto -lpng
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PNG_DEBUG 3
#include <png.h>

/**
 *
 * @param print la chaîne à afficher
 * @param prompt là où l'on doit stocker le retour
 * @param length la taille de la chaine retour
 *
 * @warning Doit libérer la chaine prompt lorsque nécessaire !
 */
void print_and_prompt(char* print, char** prompt, int* length)
{
	char c;
	int i; // Index de prompt
	int max_alloc = 20; // Longueur maximum actuel de la string
	printf("%s\n", print);
	*prompt = (char*)malloc(max_alloc);
	if ((*prompt) == NULL)
		perror("ERREUR ALLOCATION MEMOIRE STRING");
	while (1) // On saute tous les espaces de devant la saisie
	{
		c = getchar();
		if (c == EOF) break;
		if (!isspace(c))
		{
			// On remet le caractère dans stdin
			ungetc(c, stdin);
			break;
		}
	}
	while (1)
	{
		c = getchar();
		if (isspace(c) || c == EOF) // On est à la fin
		{
			(*prompt)[i] = '\0';
			break;
		}
		(*prompt)[i] = c;
		if (i == max_alloc-1) // Si buffer remplit
		{
			max_alloc += max_alloc;
			(*prompt) = (char*) realloc(*prompt, max_alloc);
			if ((*prompt) == NULL)
				perror("ERREUR RE-ALLOCATION MEMOIRE STRING");
		}
		i++;
	}
	if (length != NULL) *length = i;
}

/* PNG STUFF */

typedef struct png_t {
	int x, y;

	int width, height;
	png_byte color_type;
	png_byte bit_depth;

	png_structp png_ptr;
	png_infop info_ptr;
	int number_of_passes;
	png_bytep * row_pointers;
} png_t;

void abort_(const char * s, ...)
{
		va_list args;
		va_start(args, s);
		vfprintf(stderr, s, args);
		fprintf(stderr, "\n");
		va_end(args);
		abort();
}

void read_png_file(char* file_name, png_t* png)
{
		char header[8];    // 8 is the maximum size that can be checked

		/* open file and test for it being a png */
		FILE *fp = fopen(file_name, "rb");
		if (!fp)
				abort_("[read_png_file] File %s could not be opened for reading", file_name);
		fread(header, 1, 8, fp);
		if (png_sig_cmp((unsigned char*)header, 0, 8))
				abort_("[read_png_file] File %s is not recognized as a PNG file", file_name);


		/* initialize stuff */
		png->png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

		if (!png->png_ptr)
				abort_("[read_png_file] png_create_read_struct failed");

		png->info_ptr = png_create_info_struct(png->png_ptr);
		if (!png->info_ptr)
				abort_("[read_png_file] png_create_info_struct failed");

		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[read_png_file] Error during init_io");

		png_init_io(png->png_ptr, fp);
		png_set_sig_bytes(png->png_ptr, 8);

		png_read_info(png->png_ptr, png->info_ptr);

		png->width = png_get_image_width(png->png_ptr, png->info_ptr);
		png->height = png_get_image_height(png->png_ptr, png->info_ptr);
		png->color_type = png_get_color_type(png->png_ptr, png->info_ptr);
		png->bit_depth = png_get_bit_depth(png->png_ptr, png->info_ptr);

		png->number_of_passes = png_set_interlace_handling(png->png_ptr);
		png_read_update_info(png->png_ptr, png->info_ptr);


		/* read file */
		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[read_png_file] Error during read_image");

		png->row_pointers = (png_bytep*) malloc(sizeof(png_bytep) * png->height);
		for (png->y=0; png->y < png->height; png->y++)
				png->row_pointers[png->y] = (png_byte*) malloc(png_get_rowbytes(png->png_ptr,png->info_ptr));

		png_read_image(png->png_ptr, png->row_pointers);

		fclose(fp);
}


void write_png_file(char* file_name, png_t* png)
{
		/* create file */
		FILE *fp = fopen(file_name, "wb");
		if (!fp)
				abort_("[write_png_file] File %s could not be opened for writing", file_name);


		/* initialize stuff */
		png->png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

		if (!png->png_ptr)
				abort_("[write_png_file] png_create_write_struct failed");

		png->info_ptr = png_create_info_struct(png->png_ptr);
		if (!png->info_ptr)
				abort_("[write_png_file] png_create_info_struct failed");

		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[write_png_file] Error during init_io");

		png_init_io(png->png_ptr, fp);


		/* write header */
		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[write_png_file] Error during writing header");

		png_set_IHDR(png->png_ptr, png->info_ptr, png->width, png->height,
					 png->bit_depth, png->color_type, PNG_INTERLACE_NONE,
					 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

		png_write_info(png->png_ptr, png->info_ptr);


		/* write bytes */
		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[write_png_file] Error during writing bytes");

		png_write_image(png->png_ptr, png->row_pointers);


		/* end write */
		if (setjmp(png_jmpbuf(png->png_ptr)))
				abort_("[write_png_file] Error during end of write");

		png_write_end(png->png_ptr, NULL);

		/* cleanup heap allocation */
		for (png->y=0; png->y < png->height; png->y++)
				free(png->row_pointers[png->y]);
		free(png->row_pointers);

		fclose(fp);
}

/**
 * @param png pointeur vers le png traité
 */
void process_file(png_t* png, const char const * string, const size_t longueur)
{
	int taille_dispo = 0;
	if (png_get_color_type(png->png_ptr, png->info_ptr) == PNG_COLOR_TYPE_RGB)
	{
		taille_dispo = png->height * png->width * 3;
		if (longueur*sizeof(char)*8 > taille_dispo)
		{
			perror("MESSAGE CRYPTE TROP LONG POUR STOCKAGE");
			return;
		}
		printf("%d octets disponible", taille_dispo/8);
	}
	else if (png_get_color_type(png->png_ptr, png->info_ptr) == PNG_COLOR_TYPE_RGBA)
	{
		taille_dispo = png->height * png->width * 4;
		if (longueur*sizeof(char)*8 > taille_dispo)
		{
			perror("MESSAGE CRYPTE TROP LONG POUR STOCKAGE");
			return;
		}
		
		int x = 0, y = 0;
		png_byte* row = png->row_pointers[y];
		png_byte* ptr = &(row[x*4]);
		char c;
		const char lsb = 1;
		int bitpix = 0; // RGBA = 4 bits dispo
		for (int i = 0; i < longueur; i++)
		{
			// Pour chaque bits d'un char
			for (int o = 0; o < sizeof(char)*8; o++)
			{
				// On récupère la valeur du bit voulu
				c = string[i] >> o;
				c = lsb & c;
				// Si on a fait toute la largeur, on descend à la ligne suivante
				if (x >= png->width)
				{
					x = 0;
					y++;
					row = png->row_pointers[y];
				}
				if (bitpix >= 4)
				{
					x++; // Passe au pixel suivant
					bitpix = 0;
					ptr = &(row[x*4]);
				}
				ptr[o%4] |= c;
			}
		}
		for (png->y=0; png->y < png->height; png->y++) {
			png_byte* row = png->row_pointers[png->y];
			for (png->x=0; png->x < png->width; png->x++) {
				png_byte* ptr = &(row[png->x*4]);
				printf("Pixel at position [ %d - %d ] has RGBA values: %d - %d - %d - %d\n",
				png->x, png->y, ptr[0], ptr[1], ptr[2], ptr[3]);

				/* set red value to 0 and green value to the blue one */
				ptr[0] = 0;
				ptr[1] = ptr[2];
			}
		}
	}
	else
	{
		perror("ERREUR, TYPE DE FICHIER RGB NON TRAITE");
	}
}

/* END OF PNG STUFF */

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
	const unsigned char * p = (const unsigned char*)pv;
	if (NULL == pv)
		printf("NULL");
	else
	{
		size_t i = 0;
		for (; i<len;++i)
			printf("%02X ", *p++);
	}
	printf("\n");
}

// main entrypoint
int main(int argc, char **argv)
{
	int keylength;
	printf("Give a key length [only 128 or 192 or 256!]:\n");
	scanf("%d", &keylength);

	/* generate a key with a given length */
	unsigned char aes_key[keylength/8];
	memset(aes_key, 0, keylength/8);
	if (!RAND_bytes(aes_key, keylength/8))
		exit(-1);

	size_t inputslength = 0;
	printf("Give an input's length:\n");
	scanf("%lu", &inputslength);

	/* generate input with a given length */
	unsigned char aes_input[inputslength];
	memset(aes_input, 'X', inputslength);

	/* init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
	RAND_bytes(iv_enc, AES_BLOCK_SIZE);
	memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);

	// buffers for encryption and decryption
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char enc_out[encslength];
	unsigned char dec_out[inputslength];
	memset(enc_out, 0, sizeof(enc_out));
	memset(dec_out, 0, sizeof(dec_out));

	// so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	png_t png_file;
	read_png_file("img.png", &png_file);
/* cleanup heap allocation */
		for (png_file.y=0; png_file.y < png_file.height; png_file.y++)
				free(png_file.row_pointers[png_file.y]);
		free(png_file.row_pointers);

	AES_set_decrypt_key(aes_key, keylength, &dec_key);
	AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	printf("original:\t");
	hex_print(aes_input, sizeof(aes_input));

	printf("encrypt:\t");
	hex_print(enc_out, sizeof(enc_out));

	printf("decrypt:\t");
	hex_print(dec_out, sizeof(dec_out));

	return 0;
}
