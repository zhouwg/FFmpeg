#ifndef AVUTIL_CHINADRM_CLIENT_H
#define AVUTIL_CHINADRM_CLIENT_H

#ifdef __cplusplus
    extern "C" {
#endif

typedef void *CDRMC_SessionHandle;

int CDRMC_Start(void *env, void *context, const char *asset);
int CDRMC_Stop(void);

int CDRMC_OpenSession(CDRMC_SessionHandle *ppsession);
int CDRMC_CloseSession(CDRMC_SessionHandle session);

int CDRMC_GetProvisionRequest(CDRMC_SessionHandle session, unsigned char *request, unsigned int *prequest_size);
int CDRMC_ProcessProvisionResponse(CDRMC_SessionHandle session, unsigned char *reponse, unsigned int response_size);

int CDRMC_GetLicenseRequest(CDRMC_SessionHandle session, unsigned char *drminfo, unsigned int drminfo_size, unsigned char *request, unsigned int *prequest_size);
int CDRMC_ProcessLicenseResponse(CDRMC_SessionHandle session, unsigned char *response, unsigned int response_size);

int CDRMC_ProcessNALUnits(CDRMC_SessionHandle session, int video_format, int encrypt_method, unsigned char *pin, int in_size, unsigned char **ppout, unsigned int *pout_size);

unsigned char *CDRMC_FilterURL(unsigned char *uri);

#ifdef __cplusplus
    }
#endif

#endif //AVUTIL_CHINADRM_CLIENT_H
