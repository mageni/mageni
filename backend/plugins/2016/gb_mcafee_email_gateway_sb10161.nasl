###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_email_gateway_sb10161.nasl 11473 2018-09-19 11:21:09Z asteins $
#
# McAfee Email Gateway - Application Protections Bypass
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:mcafee:email_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105806");
  script_cve_id("CVE-2016-8005");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_version("$Revision: 11473 $");

  script_name("McAfee Email Gateway - Application Protections Bypass");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10161");

  script_tag(name:"vuldetect", value:"Check the installed version and hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"MEG is vulnerable to file attachments
  containing the null character. The scanning mechanism fails to identify the
  file name properly.");
  script_tag(name:"insight", value:"The fix changes the file name processing
  functionality to remove NULL characters from the raw header value before it is
  decoded. This addresses the vulnerability, however, there is still an exploit
  situation because certain mail clients, such as Microsoft Outlook, use a '.' in
  place of the NULL. Hence, a file name of 'test<NUL>vbs' that will now be treated
  as 'testvbs' may be treated as 'test.vbs' by the mail client. In such situations
  you would need to change your File Filter rule from '*.vbs' to just '*vbs' to
  protect against the exploit.");

  script_tag(name:"affected", value:"Email Gateway 7.6");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-09-19 13:21:09 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-12 12:40:26 +0200 (Tue, 12 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

product = get_kb_item("mcafee_email_gateway/product_name");
if( ! product ) product = 'McAfee Email Gateway';

if( ! patches = get_kb_item("mcafee_email_gateway/patches") ) exit( 0 );

if (version =~ "^7\.6\.")
{
  patch = "7.6.404h1128596";
  fix = '7.6.3334.102';
}
else
 exit( 99 );

if( patch >< patches ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = product + ' (' + version + ') is missing the patch ' + patch + ' (' + fix + ').\n';
  security_message( port:0, data:report );
  exit( 0 );
}

