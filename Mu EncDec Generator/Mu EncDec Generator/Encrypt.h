#pragma  once

#include <Windows.h>

#pragma pack(1)

struct ENCDEC_FILEHEADER
{
	short sFileHeader;
	int dwSize;
};

typedef DWORD dwXORTable[4];

#pragma pack()


class CSimpleModulus
{

public:

	CSimpleModulus();
	virtual ~CSimpleModulus();

	void Init();

	DWORD m_dwModulus[4];	// 4
	DWORD m_dwEncryptionKey[4];	// 14
	DWORD m_dwDecryptionKey[4];	// 24
	DWORD m_dwXORKey[4];	// 34

protected:

	static DWORD s_dwSaveLoadXOR[4];

public:

	int Encrypt(void * lpDest, void * lpSource, int iSize);
	int Decrypt(void * lpDest, void * lpSource, int iSize);

protected:

	int EncryptBlock(void *, void *, int);
	int DecryptBlock(void *, void *);
	int CSimpleModulus::AddBits(void*lpDest,int iDestBitPos,void*lpSource,int iBitSourcePos,int iBitLen);
	void Shift(void*lpBuff,int iSize,int ShiftLen);
	int GetByteOfBit(int);

public:

	BOOL SaveAllKey(LPSTR lpszFileName);
	BOOL LoadAllKey(LPSTR lpszFileName);
	BOOL SaveEncryptionKey(LPSTR lpszFileName);
	BOOL LoadEncryptionKey(LPSTR lpszFileName);
	BOOL SaveDecryptionKey(LPSTR lpszFileName);
	BOOL LoadDecryptionKey(LPSTR lpszFileName);

protected:

	BOOL SaveKey(LPSTR lpszFileName, WORD wFileHeader, BOOL bSaveModulus, BOOL bSaveEncKey, BOOL bSaveDecKey, BOOL bSaveXORKey);
	BOOL LoadKey(LPSTR lpszFileName, WORD wFileHeader, BOOL bLoadModulus, BOOL bLoadEncKey, BOOL bLoadDecKey, BOOL bLoadXORKey);
};