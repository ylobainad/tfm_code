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

RTC_DATA_ATTR uint8_t puf[256];
RTC_DATA_ATTR uint8_t flag_puf_response = 0;
RTC_DATA_ATTR uint8_t count = 3;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void RTC_IRAM_ATTR wake_stub_take_puf(void){
    uint8_t *start = (uint8_t*)0x3ffc0000;
    uint8_t *end = (uint8_t*) 0x3ffc0020;
    int sample_size = (end - start);
    int c = 0;
    //ESP_RTC_LOGI("Creating PUF Reference Response");
    
    for(int i = 0; i< sample_size; i++){
        //ESP_RTC_LOGI("%d",  start[i]);
        for (int y = 7; y >=0; y--){
            puf[c] = ((start[i] >> y) & 1);
            ++c;
        }
    }
    flag_puf_response = 1;
    // Set the default wake stub.
        // There is a default version of this function provided in esp-idf.
    //esp_wake_stub_set_wakeup_time(0.001*1000000);
    esp_default_wake_deep_sleep();

    return;

        // Return from the wake stub function to continue
        // booting the firmware.
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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



void app_main(void){

    // Initialize the ESP-IDF logging system
//    esp_log_level_set("*", ESP_LOG_DEBUG); // Set log level to INFO
    esp_log_level_set("*", ESP_LOG_NONE); // Set log level to INFO

    // Create a task to monitor and log performance metrics
    xTaskCreate(&performance_monitor_task, "performance_monitor", 2048, NULL, 5, NULL);


    uint8_t *start = (uint8_t*)0x3ffc0000;
    uint8_t *end = (uint8_t*) 0x3ffc0020;
    int sample_size = (end - start);
    //const int wakeup_time_sec = 1;
    int b_size = sample_size * 8;
    int c = 0;

    uint8_t r_helper_data[32]; // Adjust the array size as needed
    uint8_t r_mask[32]; // Adjust the array size as needed
    size_t arrayL = sizeof(r_helper_data);
    // Read the array from flash memory
    esp_err_t ret = readArrayFromFlash("my_namespace", "helper_data", r_helper_data, &arrayL);
        if (ret == ESP_OK) {
        // Successfully retrieved the array
        // The 'myArray' variable now contains the data, and 'arrayLength' has its size
            //printf("RECOVERED DATA: ");
            for (int i = 0; i < 32; i++){
            //    printf("%d,", r_helper_data[i]);
            }
            printf("\n");
        } 
        else {
            // Handle error (e.g., key not found or read error)
            }
        // Read the array from flash memory
        esp_err_t ret2 = readArrayFromFlash("my_namespace", "mask",r_mask, &arrayL);
        if (ret2 == ESP_OK) {
        // Successfully retrieved the array
        // The 'myArray' variable now contains the data, and 'arrayLength' has its size
            //printf("RECOVERED MASK: ");
            for (int i = 0; i < 32; i++){
            //    printf("%d,", r_mask[i]);
            }
            printf("\n");
        } 

        
        flag_puf_response = 0;
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        //uint8_t n_code_word[256];
        
        //uint8_t mask[256];
        //uint8_t *mask = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        //uint8_t key[256];
        uint8_t b_key[32];
        //uint8_t stable_puf[256];
        uint8_t helper_data[256];
        
        c = 0;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //uint8_t *helper_data = (uint8_t *)malloc(sample_size * sizeof(uint8_t));

        for(int i = 0; i< sample_size; i++){
            for (int y = 7; y >=0; y--){
                helper_data[c] = ((r_helper_data[i] >> y) & 1);
                ++c;
            }
        }
        
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////        
//        uint8_t *bit_mask = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        uint8_t bit_mask[256];
        for(int i = 0; i< sample_size; i++){
            for (int y = 7; y >=0; y--){
                bit_mask[c] = ((r_mask[i] >> y) & 1);
                ++c;
            }
        }
        
//        // APLICO LA MASCARA A LA LECTURA PUF
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//        uint8_t *stable_puf = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        uint8_t stable_puf[256];
        for (int i = 0; i < b_size; i++){
            stable_puf[i] = puf[i] ^ bit_mask[i];
        }
//        //free(bit_mask);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//        uint8_t *n_code_word= (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        uint8_t n_code_word[256];
//        // CALCULO NOISY CODE WORD
        for (int i = 0; i < b_size; i++){
           n_code_word[i] = stable_puf[i] ^ helper_data[i];
        }
//        //free(stable_puf);
//        //free(helper_data);
////*************************************************************************************************************************************
//        uint8_t *mask = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
          uint8_t mask[256];
        c = 0;
        int c_ones = 0;
        int c_cero = 0;
        for (int i = 0; i < sample_size; i++){
            uint8_t tmp[8] = {0};
            for (int y = 0; y < 8; y++){
            //printf("%d", n_code_word[8*i + y]);
                tmp[y] = n_code_word[8*i + y];
                if ((n_code_word[8*i + y]) == 1){
                    ++c_ones;
                }
                else{
                    ++c_cero;
                }
            }
            if (c_cero < c_ones){

                for (int z = 0; z < 8; z++){
                    tmp[z] = tmp[z] ^ 1;
                }
            }

            for (int m = 0; m < 8; m++){
                mask[8*i + m] = tmp[m];
            }
            c_cero = 0;
            c_ones = 0;
        }
//
//        uint8_t *key = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        uint8_t key[256];
////*************************************************************************************************************************************
        for (int i = 0; i < b_size; i++){
            key[i] = stable_puf[i] ^ mask[i];
        }
////**    ***********************************************************************************************************************************
        int tmp = 0;
        //uint8_t b_key[32];
        c = 0;
        for(int i = 0; i< 32; i++){
            for (int y = 7; y >= 0; y--){
                tmp  =  ((key[c] << y) | tmp);
                ++c;
            }
            b_key[i] = tmp;
            tmp = 0;
        }
//
//        //free(key);
        //printf("\n");    
        //printf("KEY: ");
        for (int i = 0; i < 32; i++){
            //printf("%d,", b_key[i]);
        }

        // HASH KEY

        size_t binaryDataLength = sizeof(b_key);
        // Calculate the size of the char buffer (two characters for each byte plus one for the null terminator)
        size_t charBufferSize = (binaryDataLength * 2) + 1;
        // Allocate a char buffer
        char charBuffer[charBufferSize];

        // Convert binary to char
        binaryToChar(b_key, binaryDataLength, charBuffer, charBufferSize);

       // Buffer to store the calculated SHA-256 hash (32 bytes)
        unsigned char hash[32];

        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0); // 0 means using SHA-256

        // Update the hash calculation with the message data
        //mbedtls_sha256_update(&ctx, (const unsigned char*)message, strlen(message));
        mbedtls_sha256_update(&ctx, (const unsigned char*)charBuffer, strlen(charBuffer));

        // Finalize the hash calculation
        mbedtls_sha256_finish(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        // Print the calculated SHA-256 hash
        //for (int i = 0; i < sizeof(hash); i++) {
        //    printf("%02x", hash[i]);
        //}

        // CONVIERTO R_PUF EN BYTES
        tmp = 0;
        //uint8_t rpuf_b[32];
        uint8_t *rpuf_b = (uint8_t *)malloc(sample_size * sizeof(uint8_t));
        c = 0;
        for(int i = 0; i< 32; i++){
            for (int y = 7; y >= 0; y--){
            tmp  =  ((puf[c] << y) | tmp);
            ++c;
            }
            rpuf_b[i] = tmp;
            tmp = 0;
        }

        printf("\n");    
        printf("PUF_RESPONSE: ");
        for (int i = 0; i < 32; i++){
            printf("%d,", rpuf_b[i]);
        }

        printf("\n");    
        printf("PASSWORD: ");
        for (int i = 0; i < 32; i++){
            printf("%02x", hash[i]);
        }


        printf("\n");
//        ESP_RTC_LOGI("LEN %d:", sizeof(b_key));

        if (count > 0){
            ESP_RTC_LOGI("Count: %d", count);
            --count;
            esp_sleep_enable_timer_wakeup(0.001 * 1000000);
            esp_set_deep_sleep_wake_stub(&wake_stub_take_puf);
            // Print status.
            ESP_RTC_LOGI("wake stub: going to deep sleep");
            // Set stub entry, then going to deep sleep again.
            esp_deep_sleep_start();
        }
        else{
            printf("FINISH");
        }

}   
