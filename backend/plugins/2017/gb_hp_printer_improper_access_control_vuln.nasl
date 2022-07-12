###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printer_improper_access_control_vuln.nasl 12467 2018-11-21 14:04:59Z cfischer $
#
# HP Printer Wi-Fi Direct Improper Access Control Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807397");
  script_version("$Revision: 12467 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-14 12:24:12 +0530 (Tue, 14 Feb 2017)");
  script_name("HP Printer Wi-Fi Direct Improper Access Control Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed", "target_is_printer");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://neseso.com/advisories/NESESO-2017-0111.pdf");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017020027");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04577030");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04090221");
  script_xref(name:"URL", value:"http://007software.net/hp-printers-wi-fi-direct-improper-access-control");

  script_tag(name:"summary", value:"This host is running HP Printer and is
  prone to improper access control vulnerability.");

  script_tag(name:"vuldetect", value:"Get the running version of the printer
  with the help of detect NVT and try to access restricted pages for checking
  vulnerable or not.");

  script_tag(name:"insight", value:"HP printers with Wi-Fi Direct support,
  let you print from a mobile device directly to the printer without connecting
  to a wireless network. Several of these printers are prone to a security
  vulnerability that allows an external system to obtain unrestricted remote
  read/write access to the printer configuration using the embedded web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  un authenticated users to access certain files on the target system that are
  not intended to be shared with them.");

  script_tag(name:"affected", value:"HP OfficeJet Pro 8710 firmware version WBP2CN1619BR

  HP OfficeJet Pro 8620 firmware version FDP1CN1547AR");

  script_tag(name:"solution", value:"Apply the some mitigation actions:
  Disable Wi-Fi Direct functionality to protect your device.
  Enable Password Settings on the Embedded Web Server.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

hpPort = get_kb_item("hp_printer/port");
if(!hpPort){
  hpPort = 0;
}

fw_ver = get_kb_item("hp_fw_ver");
if(!fw_ver){
  exit(0);
}

model = get_kb_item("hp_model");
if(!model){
  exit(0);
}

if("Officejet Pro 8620" >< model || "Officejet Pro 8710" >< model)
{
  if("WBP2CN1619BR" == fw_ver || "FDP1CN1547AR" == fw_ver)
  {
    vuln_url = "/DevMgmt/Email/Contacts";

    if(http_vuln_check(port:hpPort, url:vuln_url , check_header:TRUE,  pattern:"<emaildyn:EmailContacts xmlns:dd=",
       extra_check:make_list("www.hp.com", "xmlns:emaildyn=", "emailservicedyn", "dictionaries")))
    {
      report = report_vuln_url(port:hpPort, url:vuln_url);
      security_message(port:hpPort, data:report);
      exit(0);
    }
  }
}
