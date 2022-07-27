###############################################################################
# OpenVAS Vulnerability Test
#
# Synology DiskStation Manager (DSM) Multiple Vulnerabilities(Synology-SA-17:29)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/o:synology:dsm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813737");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-9553", "CVE-2017-9554");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-31 12:20:00 +0530 (Tue, 31 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Synology DiskStation Manager (DSM) Multiple Vulnerabilities(Synology-SA-17:29)");

  script_tag(name:"summary", value:"This host is running Synology DiskStation
  Manager (DSM) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check if response is confirming valid username information.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A design flaw in Synology DiskStation Manager (DSM).

  - An information exposure vulnerability in Synology DiskStation Manager (DSM).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the encryption protection mechanism and steal account,
  password details. Also attacker can obtain user information via a brute-force
  attack.");

  script_tag(name:"affected", value:"Synology DiskStation Manager (DSM) versions
  5.2, 6.0 and 6.1");

  script_tag(name:"solution", value:"Upgrade to Synology DiskStation Manager (DSM)
  version 6.1.3-15152 or 6.0.3-8754-4 or 5.2-5967-04 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_29_DSM");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43455");
  script_xref(name:"URL", value:"https://www.synology.com/en-global/dsm");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_detect.nasl");
  script_mandatory_keys("synology_dsm/installed");
  script_require_ports("Services/www", 5000, 5001);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!dsmPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Vulnerable set-up will return either 'msg : 1' if valid username,
## or 'msg : 2' if invalid username. Non-Vulnerable set-up will return 'msg : 3'
url = "/webman/forget_passwd.cgi?user=admin" ;
req = http_get_req(port:dsmPort, url:url);
res = http_keepalive_send_recv(port:dsmPort, data:req);

if(res =~ "HTTP/1.. 200 OK")
{
  ## Fixed versions
  if('"msg" : 3' >< res){
    exit(0);
  }

  ## Vulnerable versions
  if(('"msg" : 1' >< res || '"msg" : 2' >< res) && '"info" : "' >< res)
  {
    report = report_vuln_url(port:dsmPort, url: url);
    security_message(port:dsmPort, data: report);
    exit(0);
  }
}
