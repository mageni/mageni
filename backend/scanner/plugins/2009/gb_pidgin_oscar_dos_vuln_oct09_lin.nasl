###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_oscar_dos_vuln_oct09_lin.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# Pidgin Oscar Protocol Denial of Service Vulnerability (Linux)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:pidgin:pidgin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801031");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3615");
  script_bugtraq_id(36719);
  script_name("Pidgin Oscar Protocol Denial of Service Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37072");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53807");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=41");
  script_xref(name:"URL", value:"http://developer.pidgin.im/wiki/ChangeLog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_lin.nasl");
  script_mandatory_keys("Pidgin/Lin/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a Denial of Service.");

  script_tag(name:"affected", value:"Pidgin version prior to 2.6.3 on Linux.");

  script_tag(name:"insight", value:"This issue is caused by an error in the Oscar protocol plugin when processing
  malformed ICQ or AIM contacts sent by the SIM IM client, which could cause an
  invalid memory access leading to a crash.");

  script_tag(name:"summary", value:"This host has Pidgin installed and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.6.3.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:ver, test_version:"2.6.3")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.6.3");
  security_message(data:report);
  exit(0);
}

exit(99);