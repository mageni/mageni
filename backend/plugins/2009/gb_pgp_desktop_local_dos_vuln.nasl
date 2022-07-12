###############################################################################
# OpenVAS Vulnerability Test
#
# PGP Desktop Local Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800600");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0681");
  script_bugtraq_id(34490);
  script_name("PGP Desktop Local Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33310/");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2009-01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/502633");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code with
  system privileges or to crash the application.");
  script_tag(name:"affected", value:"PGP Desktop prior to version 9.10 on Windows.");
  script_tag(name:"insight", value:"IOCTL handler in 'pgpdisk.sys' and 'pgpwded.sys' files does not adequately
  validate buffer data associated with the Irp object.");
  script_tag(name:"solution", value:"Upgrade to PGP Desktop 9.10.");
  script_tag(name:"summary", value:"This host has PGP Desktop is installed and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pgpVer = get_kb_item("PGPDesktop/Win/Ver");
if(!pgpVer)
  exit(0);

if(version_is_less(version:pgpVer, test_version:"9.10.0.500")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
