# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140500");
  script_version("2023-09-22T16:08:59+0000");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-11-16 08:54:19 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CODESYS Service Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1200, 1217, 2455, 11740);

  script_tag(name:"summary", value:"TCP based detection of services supporting / using the CODESYS
  programming interface / runtime.");

  script_xref(name:"URL", value:"https://www.codesys.com");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ports = unknownservice_get_ports(default_port_list: make_list(1200, 1217, 2455, 11740));

foreach port (ports) {
  if (!soc = open_sock_tcp(port))
    continue;

  proto_version = NULL;
  os_name = NULL;
  deviceIpAddress = NULL;

  # CODESYS v2 based on https://github.com/digitalbond/Redpoint/blob/master/codesys-v2-discover.nse

  # little endian query
  lile_query = raw_string(0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01);
  # big endian query
  bige_query = raw_string(0xbb, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x01);

  send(socket: soc, data: lile_query);
  recv = recv(socket: soc, length: 512);

  if (!recv) {
    send(socket: soc, data: bige_query);
    recv = recv(socket: soc, length: 512);
  }

  close(soc);

  if (recv && strlen(recv) >= 130 && hexstr(substr(recv, 0, 1)) == "bbbb") {
    os_name = bin2string(ddata:substr(recv, 64, 95), noprint_replacement: "");
    os_details = bin2string(ddata:substr(recv, 96, 127), noprint_replacement: "");
    type = bin2string(ddata:substr(recv, 128, 159), noprint_replacement: "");
    proto_version = "2";
  } else {

    # nb: Just some "unknown" banner reporting if the service is not detected so far.
    if (recv)
      unknown_banner_set(port: port, banner: recv, set_oid_based: TRUE);

    # CODESYS v3 based on https://github.com/nmap/nmap/pull/1210

    # The v2 probe might trigger a close on the server side so we need to open a new socket.
    if (!soc = open_sock_tcp(port))
      continue;

    query = raw_string(0x00, 0x01, 0x17, 0xe8, 0x24, 0x00, 0x00, 0x00,
                       0xc5, 0x6b, 0x40, 0x03, 0x00, 0x43, 0x2d, 0xdc,
                       0x00, 0x00, 0x00, 0x00, 0x2d, 0xdf, 0x7f, 0x00,
                       0x00, 0x01, 0x83, 0x01, 0x02, 0xc2, 0x00, 0x04,
                       0x00, 0x00, 0x00, 0x00);

    send(socket: soc, data: query);
    recv = recv(socket: soc, length: 512);
    close(soc);

    if (!recv)
      continue;

    if (strlen(recv) < 75 || hexstr(substr(recv, 0, 3)) != "000117e8") {
      unknown_banner_set(port: port, banner: recv, set_oid_based: TRUE);
      continue;
    }

    buf = substr(recv, 24, 27);
    deviceIpAddress = ord(buf[0]) + "." + ord(buf[1]) + "." + ord(buf[2]) + "." + ord(buf[3]);
    buf = substr(recv, 56, 59);
    targetVersion = ord(buf[3]) + "." + ord(buf[2]) + "." + ord(buf[1]) + "." + ord(buf[0]);
    buf = substr(recv, 75);
    buf = split(buf, sep: raw_string(0x00, 0x00, 0x00), keep: FALSE);
    if (max_index(buf) >= 3) {
      deviceName = bin2string(ddata: buf[0], noprint_replacement: "");
      targetName = bin2string(ddata: buf[1], noprint_replacement: "");
      targetVendor = bin2string(ddata: buf[2], noprint_replacement: "");
    }

    proto_version = "3";
  }

  if (os_name || deviceIpAddress) {
    set_kb_item(name: "codesys/detected", value: TRUE);
    set_kb_item(name: "codesys/tcp/detected", value: TRUE);
    set_kb_item(name: "codesys/" + port + "/proto_version", value: proto_version);

    service_register(port: port, proto: "codesys");

    report = "A CODESYS version " + proto_version +
             ' service is running at this port.\n\nThe following information was extracted:\n\n';

    # v2 info
    if (os_name) {
      # nb: Just to make sure that the "right" version is saved (we also need to use
      # replace_kb_item() here).
      replace_kb_item(name: "codesys/" + port + "/proto_version", value: "2");
      set_kb_item(name: "codesys/os_name", value: os_name);
      set_kb_item(name: "codesys/" + port + "/os_name", value: os_name);
      set_kb_item(name: "codesys/os_details", value: os_details);
      set_kb_item(name: "codesys/" + port + "/os_details", value: os_details);

      report += "OS Name:       " + os_name + '\n';
      report += "OS Details:    " + os_details + '\n';
      report += "Product Type:  " + type;
    }
    # v3 info
    else {
      # nb: Just to make sure that the "right" version is saved (we also need to use
      # replace_kb_item() here).
      replace_kb_item(name: "codesys/" + port + "/proto_version", value: "3");
      set_kb_item(name: "codesys/" + port + "/targetVersion", value: targetVersion);
      set_kb_item(name: "codesys/" + port + "/targetName", value: targetName);
      set_kb_item(name: "codesys/" + port + "/targetVendor", value: targetVendor);

      report += "targetName:      " + targetName + '\n';
      report += "targetVendor:    " + targetVendor + '\n';
      report += "targetVersion:   " + targetVersion + '\n';
      report += "deviceName:      " + deviceName + '\n';
      report += "deviceIpAddress: " + deviceIpAddress;
    }

    log_message(port: port, data: report);
  }
}

exit(0);
