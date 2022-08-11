###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_apr_n_apr_util_iof_vuln.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# Apache APR and APR-util Multiple Integer Overflow Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800679");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-17 14:35:19 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_name("Apache APR and APR-util Multiple Integer Overflow Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36138");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36140");
  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/patches/apr-0.9-CVE-2009-2412.patch");
  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/patches/apr-util-0.9-CVE-2009-2412.patch");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apache_apr-utils_detect.nasl", "gb_apache_apr_detect.nasl");
  script_mandatory_keys("Apache/APR_or_Utils/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of an affected application, and can cause Denial of Service.");
  script_tag(name:"affected", value:"Apache APR version 0.9.x and 1.3.x before 1.3.8
  Apache APR-Utils version 0.9.x and 1.3.x before 1.3.9");
  script_tag(name:"insight", value:"The following issues exist:

  - An error exists when vectors trigger crafted calls to the allocator_alloc
    or apr_palloc function in memory/unix/apr_pools.c in APR.

  - An error in apr_rmm_malloc, apr_rmm_calloc or apr_rmm_realloc function in
    misc/apr_rmm.c is caused while aligning relocatable memory blocks in
    APR-util.");
  script_tag(name:"summary", value:"The host is installed with Apache APR and APR-Util and is prone to
  multiple Integer Overflow vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Apache APR version 1.3.8 or APR-util version 1.3.9 or
  apply the patches for Apache APR-Utils 0.9.x or Apache APR version 0.9.x. Please see the references for more information.


  *****

  NOTE: Ignore this warning if above mentioned patch is already applied.

  *****");
  exit(0);
}


include("version_func.inc");

apruVer = get_kb_item("Apache/APR-Utils/Ver");
aprVer = get_kb_item("Apache/APR/Ver");

# Apache APR-util
if(apruVer != NULL)
{
  if(version_in_range(version:apruVer, test_version:"0.9.0", test_version2:"0.9.17")||
     version_in_range(version:apruVer, test_version:"1.3.0", test_version2:"1.3.8")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

# Apache APR
if(aprVer != NULL)
{
  if(version_in_range(version:aprVer, test_version:"0.9.0", test_version2:"0.9.18")||
     version_in_range(version:aprVer, test_version:"1.3.0", test_version2:"1.3.7")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
