//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* Author: Yorlandy Lobaina */

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_sleep.h"
#include "esp_wake_stub.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "esp_log.h"

// counter value, stored in RTC memory
RTC_DATA_ATTR int sample_count = 0;
RTC_DATA_ATTR int wake_count = 1000;
RTC_DATA_ATTR uint16_t acc[256];
RTC_DATA_ATTR uint8_t bit_mask[256];
RTC_DATA_ATTR uint8_t puf[256];
RTC_DATA_ATTR uint8_t flag_puf = 0;
RTC_DATA_ATTR uint8_t flag_puf_reconstruction = 0;
RTC_DATA_ATTR int n_samples = 1000;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// wake up stub function stored in RTC memory
void RTC_IRAM_ATTR wake_stub_mask_creation(void){
    
    int c = 0;
    uint8_t *start = (uint8_t*)0x3ffc0000;
    uint8_t *end = (uint8_t*) 0x3ffc0020;
    
    int sample_size = (end - start);

    // Print the counter value and wakeup cause.
    ESP_RTC_LOGI("wake stub: Taking sample #: %d", sample_count);

    if (wake_count > 0) {

        for(int i = 0; i< sample_size; i++){
            ESP_RTC_LOGI("%d",  start[i]);
            for (int y = 7; y >=0; y--){
                acc[c] = ((start[i] >> y) & 1) + acc[c];
                ++c;
            }
        }
        --wake_count;
        ++sample_count;

        // Set wakeup time in stub, if need to check GPIOs or read some sensor periodically in the stub.
        //esp_wake_stub_set_wakeup_time(0.0001*1000000);
        // Print status.
        ESP_RTC_LOGI("wake stub: going to deep sleep");

        // Set stub entry, then going to deep sleep again.
        esp_wake_stub_sleep(&wake_stub_mask_creation);
    }

    else
    {
        // CREANDO LA MASCARA
        double avg;
        for (int i = 0; i < (sample_size * 8); i++){
            //printf("%d,", acc[i]);
            avg = acc[i]/(double)(n_samples);
            //printf("%f\n", avg);

            if (avg >= 1 - 0.001){
//            if (avg >= 1 - 0.001){
                bit_mask[i] = 1;
            }
            else if (avg <= 0.001){
//            else if (avg <= 0.001){
                bit_mask[i] = 1;
            }
            else{
                bit_mask[i] = 0;
            }
        }
        // Set the default wake stub.
        // There is a default version of this function provided in esp-idf.
        esp_default_wake_deep_sleep();

        // Return from the wake stub function to continue
        // booting the firmware.
        return;
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void RTC_IRAM_ATTR wake_stub_take_puf(void){
    uint8_t *start = (uint8_t*)0x3ffc0000;
    uint8_t *end = (uint8_t*) 0x3ffc0020;
    int sample_size = (end - start);
    int c = 0;
    
    ESP_RTC_LOGI("Creating PUF Reference Response");
    
    for(int i = 0; i< sample_size; i++){
        ESP_RTC_LOGI("%d",  start[i]);
        for (int y = 7; y >=0; y--){
            puf[c] = ((start[i] >> y) & 1);
            ++c;
        }
    }
    flag_puf = 1;
    // Set the default wake stub.
        // There is a default version of this function provided in esp-idf.
    esp_default_wake_deep_sleep();

        // Return from the wake stub function to continue
        // booting the firmware.
    return;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Function to save an array to flash memory
void saveArrayToFlash(const char* namespace, const char* key, uint8_t* array, size_t length) {
    esp_err_t ret;

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // Handle error by erasing and trying again or implementing a versioning strategy
    }
    ESP_ERROR_CHECK(ret);

    // Open NVS namespace
    nvs_handle_t nvs;
    ret = nvs_open(namespace, NVS_READWRITE, &nvs);
    ESP_ERROR_CHECK(ret);

    // Save the array to flash
    ret = nvs_set_blob(nvs, key, array, length);
    ESP_ERROR_CHECK(ret);

    // Commit changes to flash
    ret = nvs_commit(nvs);
    ESP_ERROR_CHECK(ret);

    // Close NVS
    nvs_close(nvs);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Function to read an array from flash memory
esp_err_t readArrayFromFlash(const char* namespace, const char* key, uint8_t* array, size_t* length) {
    esp_err_t ret;

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // Handle error by erasing and trying again or implementing a versioning strategy
    }
    ESP_ERROR_CHECK(ret);

    // Open NVS namespace
    nvs_handle_t nvs;
    ret = nvs_open(namespace, NVS_READONLY, &nvs);
    ESP_ERROR_CHECK(ret);

    // Get the size of the array in flash
    ret = nvs_get_blob(nvs, key, NULL, length);
    if (ret != ESP_OK) {
        nvs_close(nvs);
        return ret; // Key not found or error occurred
    }

    // Read the array from flash
    ret = nvs_get_blob(nvs, key, array, length);
    if (ret != ESP_OK) {
        nvs_close(nvs);
        return ret; // Error occurred while reading
    }

    // Close NVS
    nvs_close(nvs);

    return ESP_OK;
}

void binaryToChar(uint8_t* binaryData, size_t binaryDataLength, char* charBuffer, size_t bufferSize) {
    if (binaryData == NULL || charBuffer == NULL || bufferSize < (binaryDataLength * 2 + 1)) {
        // Handle invalid input or buffer size too small
        return;
    }

    for (size_t i = 0; i < binaryDataLength; i++) {
        snprintf(&charBuffer[i * 2], 3, "%02X", binaryData[i]);
    }

    charBuffer[binaryDataLength * 2] = '\0'; // Null-terminate the string
}

static const char *TAG = "performance";

void performance_monitor_task(void *pvParameter) {
    while (1) {
        // Log the current free heap size (memory usage)
        ESP_LOGI(TAG, "Free heap size: %ld bytes", esp_get_free_heap_size());

        // Log the core ID of the CPU running this task
        ESP_LOGI(TAG, "Running on CPU core %u", xPortGetCoreID());

        // Delay for a few seconds before logging again
        vTaskDelay(pdMS_TO_TICKS(5000)); // Log every 5 seconds
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void app_main()
{
    // Initialize the ESP-IDF logging system
    esp_log_level_set("*", ESP_LOG_DEBUG); // Set log level to INFO

    // Create a task to monitor and log performance metrics
    xTaskCreate(&performance_monitor_task, "performance_monitor", 2048, NULL, 5, NULL);


    uint8_t *start = (uint8_t*)0x3ffc0000;
    uint8_t *end = (uint8_t*) 0x3ffc0020;
    int sample_size = (end - start);
    const int wakeup_time_sec = 0.0001;
    int b_size = sample_size * 8;
    int c = 0;

//************************************************************************************************************************

//*********************************************************************************************************************    

    if (wake_count == 0){
    
        if (flag_puf == 0){
            // HAGO UNA LECTURA ADICIONAL PARA USARLA COMO REFERENCE_PUF_RESPONSE
                esp_sleep_enable_timer_wakeup(wakeup_time_sec * 1000000);
                esp_set_deep_sleep_wake_stub(&wake_stub_take_puf);
                printf("Entering deep sleep\n");
                esp_deep_sleep_start();
        }
        flag_puf = 0;
        uint8_t *r_puf = (uint8_t *)malloc(b_size * sizeof(uint8_t));
        //************************************************************************************************************
        // APLICO LA MASCARA AL REFERENCE_PUF_RESPONSE
        for (int i = 0; i < b_size; i++){
            r_puf[i] = puf[i] & bit_mask[i];
        }
        // CONVIERTO R_PUF EN BYTES
        uint8_t tmp = 0;
        //uint8_t rpuf_b[32];
        uint8_t *rpuf_b = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        c = 0;
        for(int i = 0; i< 32; i++){
            for (int y = 7; y >= 0; y--){
            tmp  =  ((r_puf[c] << y) | tmp);
            ++c;
            }
            rpuf_b[i] = tmp;
            tmp = 0;
        }
        //************************************************************************************************************
        uint8_t *code_word = (uint8_t *)malloc(b_size * sizeof(uint8_t));
        // CALCULO EL CODE_WORD
        c = 0;
        for (int i = 0; i < sample_size; i++){
            if((r_puf[i*8]) == 1){
                for (int y = 0; y < 8; y++){
                    code_word[c] = 1;
                    c++;
                }
            }
            else{
                for (int y = 0; y < 8; y++){
                    code_word[c] = 0;
                    c++;
                }
            }
        }
        printf("\n");
        c = 0;
        //printf("CODE WORD: ");
        for (int i = 0; i < b_size; i++){
        //    printf("%d,", code_word[i]);
        }
        //************************************************************************************************************
        // CALCULO EL HELPER_DATA  
        uint8_t *helper_data = (uint8_t *)malloc(b_size * sizeof(uint8_t));      
        for (int i = 0; i < b_size; i++){
            helper_data[i] = code_word[i] ^ r_puf[i];
            //printf("%d,", helper_data[i]);
        }
        // printf("\n");
        free(code_word);
        tmp = 0;
        //uint8_t b_hp[32];
        uint8_t *b_hd = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        c = 0;
        for(int i = 0; i< 32; i++){
            for (int y = 7; y >= 0; y--){
                tmp  =  ((helper_data[c] << y) | tmp);
                ++c;
            }
            b_hd[i] = tmp;
            tmp = 0;
        }
        printf("HELPER DATA: ");
            for (int i = 0; i < 32; i++){
                printf("%d,", b_hd[i]);
            }
            printf("\n");
        //************************************************************************************************************
        int arrayLength = sample_size;
        saveArrayToFlash("my_namespace", "helper_data", b_hd, arrayLength);
        free(b_hd);
        //************************************************************************************************************
        tmp = 0;
        //uint8_t b_mask[32];
        uint8_t *b_mask = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        c = 0;
        for(int i = 0; i< 32; i++){
            for (int y = 7; y >= 0; y--){
                tmp  =  ((bit_mask[c] << y) | tmp);
                ++c;
            }
            b_mask[i] = tmp;
            tmp = 0;
        }
        // IMPRIMO LA MASCARA  
        printf("MASK: ");
        for (int i = 0; i < 32; i++){
            printf("%d,", b_mask[i]);
        }
        printf("\n");
        //************************************************************************************************************
        saveArrayToFlash("my_namespace", "mask", b_mask, arrayLength);
        free(b_mask);
        //************************************************************************************************************
        // IMPRIMO LA CLAVE  
        printf("KEY: ");
        for (int i = 0; i < sample_size; i++){
            printf("%d", rpuf_b[i]);
        }
        printf("\n");
        free(rpuf_b);
        //************************************************************************************************************
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        esp_err_t ret0;
        // Initialize NVS
        ret0 = nvs_flash_init();
        if (ret0 == ESP_ERR_NVS_NO_FREE_PAGES || ret0 == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            // Handle error by erasing and trying again or implementing a versioning strategy
        }
        ESP_ERROR_CHECK(ret0);
                // Open NVS namespace (create if it doesn't exist)
        nvs_handle_t nvs;
        ret0 = nvs_open("my_namespace", NVS_READWRITE, &nvs);
        ESP_ERROR_CHECK(ret0);
                // Define the key and the value you want to save
        const char* key = "writted";
        int32_t value_to_save = 1;
                // Save the value to flash memory
        ret0 = nvs_set_i32(nvs, key, value_to_save);
        if (ret0 != ESP_OK) {
            // Handle error
            printf("Error saving value to NVS: %s\n", esp_err_to_name(ret0));
        } else {
            printf("Value saved successfully.\n");
        }
                // Commit changes to flash
        ret0 = nvs_commit(nvs);
        if (ret0 != ESP_OK) {
            // Handle error
            printf("Error committing changes to NVS: %s\n", esp_err_to_name(ret0));
        }
                // Close NVS
        nvs_close(nvs);
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        printf("Finish\n");
    }
    else {
        printf("Enabling timer wakeup, %ds\n", wakeup_time_sec);
        esp_sleep_enable_timer_wakeup(wakeup_time_sec * 1000000);
        esp_set_deep_sleep_wake_stub(&wake_stub_mask_creation);
        printf("Entering deep sleep\n");
        esp_deep_sleep_start();
    }
    

}
