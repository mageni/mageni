# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900811");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Asterisk PBX Detection (SIP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"SIP based detection of Asterisk PBX.");

  script_xref(name:"URL", value:"https://www.asterisk.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("sip.inc");
include("os_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto(default_port:"5060", default_proto:"udp");
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port:port, proto:proto);

if(banner && ("Asterisk PBX" >< banner || "FPBX-" >< banner)) {

  version = "unknown";

  asteriskVer = eregmatch(pattern:"Asterisk PBX (certified/)?([0-9.]+(.?[a-z0-9]+)?)", string:banner);

  if(!isnull(asteriskVer[2])) {
    version = ereg_replace(pattern:"-", replace:".", string:asteriskVer[2]);
    set_kb_item(name:"digium/asterisk/version", value:version);
  } else {
    vers = eregmatch(pattern:'FPBX-[0-9.]+\\(([0-9.]+[^)]+)\\)', string:banner);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name:"digium/asterisk/version", value:version);
    }
  }

  set_kb_item(name:"digium/asterisk/detected", value:TRUE);
  cpe = build_cpe(value:version, exp:"^([0-9.]+\.[0-9]+)\.?((rc[0-9]+)|(cert[1-9]))?", base:"cpe:/a:digium:asterisk:");
  if(!cpe)
    cpe = "cpe:/a:digium:asterisk";

  os_register_and_report(os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port,
                         desc:"Asterisk PBX Detection (SIP)", runs_key:"unixoide");

  location = port + "/" + proto;

  register_product(cpe:cpe, port:port, location:location, service:"sip", proto:proto);
  log_message(data: build_detection_report(app:"Asterisk PBX", version:version, install:location, cpe:cpe, concluded:banner),
                                             port:port, proto:proto);
}

exit(0);
