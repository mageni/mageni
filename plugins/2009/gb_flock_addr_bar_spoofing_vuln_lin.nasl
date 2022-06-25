###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flock_addr_bar_spoofing_vuln_lin.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Flock Address Bar Spoofing Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800880");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3007");
  script_name("Flock Address Bar Spoofing Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flock_detect_lin.nasl");
  script_mandatory_keys("Flock/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation lets the attackers to spoof parts of the
address bar and modify page content on a host that a user may consider partly
trusted.");
  script_tag(name:"affected", value:"Flock version 2.5.1 on Linux.");
  script_tag(name:"insight", value:"Error exists when opening a new window using 'window.open()',
which can be exploited to display spoofed content in the browser window while
the address bar shows an arbitrary path on a possibly trusted host.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Flock Browser and is prone to Address
Bar Spoofing vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

# Flock Check
flockVer = get_kb_item("Flock/Linux/Ver");

if(flockVer != NULL)
{
  if(version_is_equal(version:flockVer, test_version:"2.5.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
