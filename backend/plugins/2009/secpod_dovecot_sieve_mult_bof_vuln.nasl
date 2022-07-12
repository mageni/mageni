###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dovecot_sieve_mult_bof_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Dovecot Sieve Plugin Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901026");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3235");
  script_bugtraq_id(36377);
  script_name("Dovecot Sieve Plugin Multiple Buffer Overflow Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53248");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2641");
  script_xref(name:"URL", value:"http://www.dovecot.org/list/dovecot-news/2009-September/000135.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"impact", value:"Successful attack could allow malicious people to crash an affected
  application or execute arbitrary code.");

  script_tag(name:"affected", value:"Dovecot versions 1.0 before 1.0.4 and 1.1 before 1.1.7");

  script_tag(name:"insight", value:"Multiple buffer overflow errors in the CMU libsieve when processing
  malicious SIEVE scripts.");

  script_tag(name:"summary", value:"This host has Dovecot Sieve Plugin installed and is prone to
  multiple Buffer Overflow Vulnerabilities");

  script_tag(name:"solution", value:"Apply the patch  or upgrade to Dovecot version 1.1.4 or 1.1.7");

  script_xref(name:"URL", value:"http://www.dovecot.org/download.html");
  script_xref(name:"URL", value:"http://hg.dovecot.org/dovecot-sieve-1.1/rev/049f22520628");
  script_xref(name:"URL", value:"http://hg.dovecot.org/dovecot-sieve-1.1/rev/4577c4e1130d");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include("host_details.inc");
include("version_func.inc");

if( ! dovecotVer = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_in_range( version: dovecotVer, test_version: "1.0", test_version2: "1.0.3" ) ||
    version_in_range( version: dovecotVer, test_version: "1.1", test_version2: "1.1.6" ) ) {
  report = report_fixed_ver(installed_version:dovecotVer, fixed_version:"1.1.4/1.1.7");
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );