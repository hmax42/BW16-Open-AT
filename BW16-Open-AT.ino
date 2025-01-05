/*
 Advanced dual channel WiFi Scan example for Ameba 

 This example scans for available Wifi networks using the build in functionality.
 Every 3 seconds, it scans again. 
 It doesn't actually connect to any network.

 based on the work of https://gist.github.com/EstebanFuentealba/3da9ccecefa7e1b44d84e7cfaad2f35f
 */

const byte numChars = 64;
char receivedChars[numChars];
boolean newData = false;

#include <WiFi.h>
#include <wifi_conf.h>

// The SDK sets the maximum number of wifi networks found to be 50. We need more for wardriving
// in dense areas.
#ifdef WL_NETWORKS_LIST_MAXNUM //if the macro WL_NETWORKS_LIST_MAXNUM is defined 
  #undef WL_NETWORKS_LIST_MAXNUM //un-define it
#endif 

#ifndef WL_NETWORKS_LIST_MAXNUM //if the macro WL_NETWORKS_LIST_MAXNUM is not defined 
  #define WL_NETWORKS_LIST_MAXNUM 64 //define it with the new value
#endif 

static uint8_t _networkCount;
static char _networkSsid[WL_NETWORKS_LIST_MAXNUM][WL_SSID_MAX_LENGTH];
static int32_t _networkRssi[WL_NETWORKS_LIST_MAXNUM];
static uint32_t _networkEncr[WL_NETWORKS_LIST_MAXNUM];
static uint8_t _networkChannel[WL_NETWORKS_LIST_MAXNUM];
static uint8_t _networkBand[WL_NETWORKS_LIST_MAXNUM];
static char _networkMac[WL_NETWORKS_LIST_MAXNUM][18];

//OTA setup 
#include <OTA.h>
#include <AmebaMDNS.h>
#define OTA_PORT 8082
OTA ota;
MDNSService service("BW16-Open-AT", "_arduino._tcp", "local", 5000);

char ssid[sizeof(receivedChars) - 6];       // your network SSID (name)
char pass[sizeof(receivedChars) - 6];           // your network password (use for WPA, or use as key for WEP)
int status = WL_IDLE_STATUS;        // Indicator of Wifi status

void setup() {
  // Initialize Serial1 and wait for port to open
  // 38400 used to match default speed of B&T AT firmware
  Serial1.begin(38400);
  while (!Serial1) {
    ;  // wait for Serial1 port to connect. Needed for native USB port only
  }
  Serial1.println("Welcome to BW16-Open-AT!");
  // Initialize the onboard WiFi and set channel plan to allow for 5GHz:
  WiFi.status();
  wifi_set_channel_plan(RTW_COUNTRY_WORLD);
}

void loop() {
  recvWithStartEndMarkers();
  if (newData) {
    Serial1.println();
    if (strcmp(receivedChars, "ATWS") == 0) {
      ATWS();
    }
    if (strcmp(receivedChars, "AT") == 0) {
      Serial1.println("OK");
    }
    if (strcmp(receivedChars, "ATAT") == 0) {
      ATAT();
    }
    if (strcmp(receivedChars, "ATOTA") == 0) {
      ATOTA();
    }
    if (strncmp(receivedChars, "ATSSID", 6) == 0) {
      strncpy(ssid, receivedChars + 6, sizeof(receivedChars) - 6);
      Serial1.println(ssid);
      Serial1.println("ATSSID OK");
    }
    if (strncmp(receivedChars, "ATPASS", 6) == 0) {
      strncpy(pass, receivedChars + 6, sizeof(receivedChars) - 6);
      Serial1.println(pass);
      Serial1.println("ATPASS OK");
    }
    newData = false;
  }
  if (_networkCount > 0) {
    printNetworkList();
    _networkCount = 0;
  }
}


// The following code is for handling the WiFi scanning.

// Scanning code taken from https://gist.github.com/designer2k2/2dc8c4a06394fdba91f3655dc9be9728
static rtw_result_t wifidrv_scan_result_handler(rtw_scan_handler_result_t *malloced_scan_result) {
  rtw_scan_result_t *record;

  if (malloced_scan_result->scan_complete != RTW_TRUE) {
    record = &malloced_scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0; /* Ensure the SSID is null terminated */

    if (_networkCount < WL_NETWORKS_LIST_MAXNUM) {
      strcpy(_networkSsid[_networkCount], (char *)record->SSID.val);
      _networkRssi[_networkCount] = record->signal_strength;
      _networkEncr[_networkCount] = record->security;
      _networkChannel[_networkCount] = record->channel;
      _networkBand[_networkCount] = record->band;
      sprintf(_networkMac[_networkCount], "%02X:%02X:%02X:%02X:%02X:%02X",
              record->BSSID.octet[0], record->BSSID.octet[1], record->BSSID.octet[2],
              record->BSSID.octet[3], record->BSSID.octet[4], record->BSSID.octet[5]);
      _networkCount++;
    }
  }
  return RTW_SUCCESS;
}

// Converts SDK identified network types to a human readable string. These strings need to match on
// in ESP-B in wardriver.uk code
String getEncryptionTypeEx(uint32_t thisType) {
  switch (thisType) {
    case RTW_SECURITY_OPEN:
    case RTW_SECURITY_WPS_OPEN:
      return "Open";
    case RTW_SECURITY_WEP_PSK:
    case RTW_SECURITY_WEP_SHARED:
      return "WEP";
    case RTW_SECURITY_WPA_TKIP_PSK:
    case RTW_SECURITY_WPA_AES_PSK:
    case RTW_SECURITY_WPA_MIXED_PSK:
      return "WPA PSK";
    case RTW_SECURITY_WPA2_AES_PSK:
    case RTW_SECURITY_WPA2_TKIP_PSK:
    case RTW_SECURITY_WPA2_MIXED_PSK:
    case RTW_SECURITY_WPA2_AES_CMAC:  //Might be incorrect because I'm a crypto noob
      return "WPA2 PSK";
    case RTW_SECURITY_WPA_WPA2_TKIP_PSK:
    case RTW_SECURITY_WPA_WPA2_AES_PSK:
    case RTW_SECURITY_WPA_WPA2_MIXED_PSK:
      return "WPA/WPA2 PSK";
    case RTW_SECURITY_WPA_TKIP_ENTERPRISE:
    case RTW_SECURITY_WPA_AES_ENTERPRISE:
    case RTW_SECURITY_WPA_MIXED_ENTERPRISE:
      return "WPA Enterprise";
    case RTW_SECURITY_WPA2_TKIP_ENTERPRISE:
    case RTW_SECURITY_WPA2_AES_ENTERPRISE:
    case RTW_SECURITY_WPA2_MIXED_ENTERPRISE:
      return "WPA2 Enterprise";
    case RTW_SECURITY_WPA_WPA2_TKIP_ENTERPRISE:
    case RTW_SECURITY_WPA_WPA2_AES_ENTERPRISE:
    case RTW_SECURITY_WPA_WPA2_MIXED_ENTERPRISE:
      return "WPA/WPA2 Enterprise";
    case RTW_SECURITY_WPA3_AES_PSK:
      return "WPA3 PSK";
    case RTW_SECURITY_WPA2_WPA3_MIXED:
      return "WPA2/WPA3 PSK";
    case RTW_SECURITY_WPS_SECURE:
    default:
      return "Unknown";
  }
}


//The following code is related to correctly handling serial input
void recvWithStartEndMarkers() {
  static boolean recvInProgress = false;
  static byte ndx = 0;
  char startMarker = 'A';
  char endMarker = '\r';
  char rc;

  while (Serial1.available() > 0 && newData == false) {
    rc = Serial1.read();
    Serial1.print(rc);
    if (recvInProgress == true) {
      if (rc != endMarker) {
        receivedChars[ndx] = rc;
        ndx++;
        if (ndx >= numChars) {
          ndx = numChars - 1;
        }
      } else {
        receivedChars[ndx] = '\0';  // terminate the string
        recvInProgress = false;
        ndx = 0;
        newData = true;
      }
    }

    else if (rc == startMarker) {
      receivedChars[ndx] = rc;
      ndx++;
      recvInProgress = true;
    }
  }
}


//The following code is for handling AT commands
static int8_t ATWS() {
  _networkCount = 0;
  if (wifi_scan_networks(wifidrv_scan_result_handler, NULL) != RTW_SUCCESS) {
    return WL_FAILURE;
  }
  return _networkCount;
}

void ATAT() {
  Serial1.println("");
  Serial1.println("                ________");
  Serial1.println("            _.-'::'\\____`.");
  Serial1.println("          ,'::::'  |,------.");
  Serial1.println("         /::::'    ||`-..___;");
  Serial1.println("        ::::'      ||   / ___\\");
  Serial1.println("        |::       _||  [ [___]]");
  Serial1.println("        |:   __,-'  `-._\\__._/");
  Serial1.println("        :_,-\\  \\| |,-'_,. . `.");
  Serial1.println("        | \\  \\  | |.-'_,-\\ \\   ~");
  Serial1.println("        | |`._`-| |,-|    \\ \\    ~");
  Serial1.println("        |_|`----| ||_|     \\ \\     ~              _");
  Serial1.println("        [_]     |_|[_]     [[_]      ~        __(  )");
  Serial1.println("        | |    [[_]| |     `| |        ~    _(   )   )");
  Serial1.println("        |_|    `| ||_|      |_|          ~ (    ) ) ))");
  Serial1.println("        [_]     | |[_]      [_]          (_       _))");
  Serial1.println("       /___\\    [ ] __\\    /___\\           (( \\   ) )");
  Serial1.println("jrei          /___\\                        (     ) )");
  Serial1.println("                                             (  #  )");
  Serial1.println("");
}

void printNetworkList() {
  for (int network = 0; network < _networkCount; network++) {
    Serial1.print("AP : ");
    Serial1.print(network + 1);
    Serial1.print(",");
    Serial1.print(_networkSsid[network]);
    Serial1.print(",");
    Serial1.print(_networkChannel[network]);
    Serial1.print(",");
    Serial1.print(getEncryptionTypeEx(_networkEncr[network]));
    Serial1.print(",");
    Serial1.print(_networkRssi[network]);
    Serial1.print(",");
    Serial1.print(_networkMac[network]);
    Serial1.println("");
  }
  Serial1.println("[ATWS]");
}

void ATOTA() {
  while (status != WL_CONNECTED) {
      Serial1.print("[MAIN] Attempting to connect to SSID: ");
      Serial1.println(ssid);
      // Connect to WPA/WPA2 network. Change this line if using open or WEP
      // network:
      status = WiFi.begin(ssid, pass);
      // wait 10 seconds for connection:
      delay(10000);
  }
  // you're connected now, so print out the status:
  printWifiStatus();

  // setup MDNS service to host OTA Server on the
  // Arduino Network Port
  beginMDNSService();

  // start connecting to OTA server and reboot 
  // with the new image
  ota.beginOTA(OTA_PORT);
}

void printWifiStatus() {
    // print the SSID of the network you're attached to:
    Serial1.println();
    Serial1.print("SSID: ");
    Serial1.println(WiFi.SSID());

    // print your WiFi shield's IP address:
    IPAddress ip = WiFi.localIP();
    Serial1.print("IP Address: ");
    Serial1.println(ip);

    // print the received signal strength:
    long rssi = WiFi.RSSI();
    Serial1.print("signal strength (RSSI):");
    Serial1.print(rssi);
    Serial1.println(" dBm");
}

void beginMDNSService() {
    service.addTxtRecord("board", strlen("ameba_rtl8721d"), "ameba_rtl8721d");
    service.addTxtRecord("auth_upload", strlen("no"), "no");
    service.addTxtRecord("tcp_check", strlen("no"), "no");
    service.addTxtRecord("ssh_upload", strlen("no"), "no");

    printf("Start mDNS service\r\n");
    MDNS.begin();

    printf("register mDNS service\r\n");
    MDNS.registerService(service);
}
