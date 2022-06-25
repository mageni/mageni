###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_info_disc_vuln_mar15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# PuTTY Information Disclosure vulnerability Mar15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805434");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2157");
  script_bugtraq_id(72825);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-31 13:05:20 +0530 (Tue, 31 Mar 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("PuTTY Information Disclosure vulnerability Mar15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with PuTTY and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the program failing to
  clear SSH-2 private key information from the memory during the saving or
  loading of key files to disk.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"PuTTY version 0.51 through 0.63 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to PuTTY version 0.64 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/02/28/4");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!puttyVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:puttyVer, test_version:"0.51", test_version2:"0.63"))
{
  report = 'Installed version: ' + puttyVer + '\n' +
           'Fixed version:     ' + "0.64" + '\n';
  security_message(data:report);
  exit(0);
}
