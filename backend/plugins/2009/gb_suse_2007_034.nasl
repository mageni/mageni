###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_034.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for asterisk SUSE-SA:2007:034
#
# Authors:
# System Generated Check
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

include("revisions-lib.inc");
tag_insight = "The Open Source PBX software Asterisk was updated
  to fix several security related bugs that allowed attackers to remotely
  crash asterisk or cause information leaks:

  - CVE-2007-1306: Asterisk allowed remote attackers to cause a denial
  of service (crash) by sending a Session Initiation Protocol (SIP)
  packet without a URI and SIP-version header, which results in a
  NULL pointer dereference.

  - CVE-2007-1561: The channel driver in Asterisk allowed remote
  attackers to cause a denial of service (crash) via a SIP INVITE
  message with an SDP containing one valid and one invalid IP address.

  - CVE-2007-1594: The handle_response function in chan_sip.c in Asterisk
  allowed remote attackers to cause a denial of service (crash)
  via a SIP Response code 0 in a SIP packet.

  - CVE-2007-1595: The Asterisk Extension Language (AEL) in pbx/pbx_ael.c
  in Asterisk does not properly generate extensions, which allows
  remote attackers to execute arbitrary extensions and have an unknown
  impact by specifying an invalid extension in a certain form.

  - CVE-2007-2294: The Manager Interface in Asterisk allowed
  remote attackers to cause a denial of service (crash) by using MD5
  authentication to authenticate a user that does not have a password
  defined in manager.conf, resulting in a NULL pointer dereference.

  - CVE-2007-2297: The SIP channel driver (chan_sip) in Asterisk did not
  properly parse SIP UDP packets that do not contain a valid response
  code, which allows remote attackers to cause a denial of service
  (crash).

  - CVE-2007-2488: The IAX2 channel driver (chan_iax2) in Asterisk
  did not properly null terminate data, which allows remote attackers
  to trigger loss of transmitted data, and possibly obtain sensitive
  information (memory contents) or cause a denial of service
  (application crash), by sending a frame that lacks a 0 byte.";

tag_impact = "remote denial of service";
tag_affected = "asterisk on SUSE LINUX 10.1, openSUSE 10.2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304674");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-1306", "CVE-2007-1561", "CVE-2007-1594", "CVE-2007-1595", "CVE-2007-2294", "CVE-2007-2297", "CVE-2007-2488");
  script_name( "SuSE Update for asterisk SUSE-SA:2007:034");

  script_tag(name:"summary", value:"Check for the Version of asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~1.2.13~23", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~1.2.5~12.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
