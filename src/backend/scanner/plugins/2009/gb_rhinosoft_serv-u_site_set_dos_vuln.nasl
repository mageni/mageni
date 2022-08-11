###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rhinosoft_serv-u_site_set_dos_vuln.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# Rhino Software Serv-U 'SITE SET' Command Denial Of Service vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801118");
  script_version("$Revision: 13568 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3655");
  script_name("Rhino Software Serv-U 'SITE SET' Command Denial Of Service vulnerability");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36873/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_rhinosoft_serv-u_detect.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ftp", 21, "Services/ssh", 22);
  script_mandatory_keys("Serv-U/FTP/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to cause a Denial of
  Service in the affected application.");

  script_tag(name:"affected", value:"Rhino Software Serv-U version prior to 9.0.0.1");

  script_tag(name:"insight", value:"An error occurs when application handles the 'SITE SET TRANSFERPROGRESS ON'
  command.");

  script_tag(name:"solution", value:"Upgrade to Rhino Software Serv-U version 9.0.0.1 or later.");

  script_tag(name:"summary", value:"This host is installed with Rhino Software Serv-U and is prone to
  Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.serv-u.com/dn.asp");
  exit(0);
}

servuVer = get_kb_item("Serv-U/FTP/Ver");
if(servuVer && servuVer =~ "^[78]\..+")
  security_message(port:0);