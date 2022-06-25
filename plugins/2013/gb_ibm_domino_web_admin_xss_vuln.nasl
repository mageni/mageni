###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_web_admin_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# IBM Lotus Domino Web Administrator Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803973");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-4055", "CVE-2013-4051", "CVE-2013-4050");
  script_bugtraq_id(63578, 63577, 63576);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-05 13:26:26 +0530 (Thu, 05 Dec 2013)");
  script_name("IBM Lotus Domino Web Administrator Cross Site Scripting Vulnerability");


  script_tag(name:"summary", value:"The host is installed with IBM Lotus Domino and is prone to cross site
scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is in the webadmin.nsf file in Domino Web Administrator which fails
to validate user supplied input properly.");
  script_tag(name:"affected", value:"IBM Lotus Domino 8.5 and 9.0");
  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to hijack
the authentication of unspecified victims.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86544");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21652988");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:domVer, test_version:"8.5.0") ||
   version_is_equal(version:domVer, test_version:"9.0.0"))
{
  security_message(port:0);
  exit(0);
}
