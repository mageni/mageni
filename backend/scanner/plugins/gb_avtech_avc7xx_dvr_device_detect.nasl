################################i###############################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_avc7xx_dvr_device_detect.nasl 10887 2018-08-10 12:05:12Z santu $
#
# AVTech AVC 7xx DVR Device Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813817");
  script_version("2019-03-27T10:56:08+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-27 10:56:08 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)");
  script_name("AVTech AVC 7xx DVR Device Detection");

  script_tag(name:"summary", value:"Detection of AVTech AVC 7xx DVR
  devices.

  This script sends an HTTP GET request to detect an AVTech AVC 7xx DVR
  device on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.avtech.hk/english/products5_1_787.htm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

#Classify the host type to later send the right POST-request to log in
if(res =~ "Server:\s*AV-TECH AV[0-9]+ Video Web Server")
  hostType = "Video_Web_Server";
else if (res =~ "Server:\s*SQ-WEBCAM")
  hostType = "SQ_Webcam";

if(res =~ "---\s*VIDEO WEB SERVER\s*---" && !isnull(hostType) && ">Username<" >< res && ">Password<" >< res) {
  version = "Unknown";
  install = "/";

  set_kb_item(name: "avtech/avc7xx/dvr/detected", value: TRUE);
  set_kb_item(name: "avtech/avc7xx/dvr/host_type", value: hostType);

  cpe = "cpe:/o:avtech:avc7xx_dvr";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "AVTech AVC 7xx DVR",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "The version is not being sent by the host.");
}

exit(0);
