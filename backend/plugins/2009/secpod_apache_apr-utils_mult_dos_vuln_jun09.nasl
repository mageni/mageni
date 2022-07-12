###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_apr-utils_mult_dos_vuln_jun09.nasl 13573 2019-02-11 11:25:59Z cfischer $
#
# Apache APR-Utils Multiple Denial of Service Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900572");
  script_version("$Revision: 13573 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:25:59 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2009-1956", "CVE-2009-0023");
  script_bugtraq_id(35221, 35251);
  script_name("Apache APR-Utils Multiple Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_apr-utils_detect.nasl");
  script_mandatory_keys("Apache/APR-Utils/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50964");
  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3");

  script_tag(name:"impact", value:"Attackers can exploit these issues to crash the application
  resulting into a denial of service conditions.");

  script_tag(name:"affected", value:"Apache APR-Utils before 1.3.5 on Linux.");

  script_tag(name:"insight", value:"The Flaws are  due to,

  - An integer underflow Error in the apr_strmatch_precompile() function
  in 'strmatch/apr_strmatch.c', while processing malicious data.

  - A Off-by-one error in the apr_brigade_vprintf function on big-endian
  platform while processing crafted input.");

  script_tag(name:"solution", value:"Apply the patches or upgrade to Apache APR-Utils 1.3.5 or later.");

  script_tag(name:"summary", value:"The host is installed with Apache APR-Utils and is prone to
  Multiple Denial of Service Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

utilsVer = get_kb_item("Apache/APR-Utils/Ver");
if(!utilsVer)
  exit(0);

if(version_is_less(version:utilsVer, test_version:"1.3.5")){
  report = report_fixed_ver(installed_version:utilsVer, fixed_version:"1.3.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);