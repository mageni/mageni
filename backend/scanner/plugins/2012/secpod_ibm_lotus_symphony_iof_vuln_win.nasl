###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_symphony_iof_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902808");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0192");
  script_bugtraq_id(51591);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-25 12:12:12 +0530 (Wed, 25 Jan 2012)");
  script_name("IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ibm_lotus_symphony_detect_win.nasl");
  script_mandatory_keys("IBM/Lotus/Symphony/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51591");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72424");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21578684");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of affected applications. Failed exploit attempts will likely
  result in denial-of-service conditions.");
  script_tag(name:"affected", value:"IBM Lotus Symphony versions 3.0.0 FP3 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error when processing embedded
  image objects. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted JPEG object within a DOC file.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Symphony version 3.0.1 or later.");
  script_tag(name:"summary", value:"This host is installed with IBM Lotus Symphony and is prone to
  integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ibm.com/software/lotus/symphony/home.nsf/home");
  exit(0);
}


include("version_func.inc");

version = get_kb_item("IBM/Lotus/Symphony/Win/Ver");

if(version_is_less(version:version, test_version:"3.0.1")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.0.1");
  security_message(data:report);
  exit(0);
}

exit(99);
