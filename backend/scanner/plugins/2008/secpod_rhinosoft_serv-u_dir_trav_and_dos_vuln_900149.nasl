##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rhinosoft_serv-u_dir_trav_and_dos_vuln_900149.nasl 12605 2018-11-30 15:22:13Z cfischer $
#
# Serv-U File Renaming Directory Traversal and 'STOU' DoS Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900149");
  script_version("$Revision: 12605 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 16:22:13 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:57:31 +0200 (Tue, 14 Oct 2008)");
  script_bugtraq_id(31563);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("Serv-U File Renaming Directory Traversal and 'STOU' DoS Vulnerabilities");
  script_dependencies("secpod_servu_ftp_server_detect.nasl");
  script_mandatory_keys("Serv-U/FTPServ/Ver");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6660");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32150/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45653");

  script_tag(name:"summary", value:"The host is running Serv-U FTP Server, which is prone to Directory
  Traversal and Denial of Service Vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to,

  - error in handling 'STOU' FTP command. It can exhaust available CPU
  resources when exploited through a specially crafted argument value.

  - input validation error in the FTP service when renaming files which can be
  exploited to overwrite or rename files via directory traversal attacks.");

  script_tag(name:"affected", value:"RhinoSoft Serv-U FTP Server 7.3.0.0 and prior");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to RhinoSoft Serv-U FTP Server 10 or later.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to write arbitrary files to
  locations outside of the application's current directory, and deny the service.");

  script_xref(name:"URL", value:"http://www.serv-u.com/dn.asp");

  exit(0);
}

servuVer = get_kb_item("Serv-U/FTPServ/Ver");
if(!servuVer){
  exit(0);
}

if(egrep(pattern:"^(7\.3(\.0(\.0)?)?)$", string:servuVer)){
  security_message(port:0);
}