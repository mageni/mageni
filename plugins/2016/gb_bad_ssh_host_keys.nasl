###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bad_ssh_host_keys.nasl 13580 2019-02-11 14:26:26Z cfischer $
#
# Known SSH Host Key
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105497");
  script_version("$Revision: 13580 $");
  script_name("Known SSH Host Key");
  script_cve_id("CVE-2015-6358", "CVE-2015-7255", "CVE-2015-7256", "CVE-2015-7276", "CVE-2015-8251",
                "CVE-2015-8260", "CVE-2009-4510", "CVE-2008-0166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 15:26:26 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-01-05 13:21:28 +0100 (Tue, 05 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("SSH/fingerprints/available");

  script_xref(name:"URL", value:"https://blog.shodan.io/duplicate-ssh-keys-everywhere/");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/566724");
  script_xref(name:"URL", value:"http://blogs.intevation.de/thomas/hetzner-duplicate-ed25519-ssh-host-keys/");
  script_xref(name:"URL", value:"https://www.vsecurity.com/download/advisories/20100409-2.txt");
  script_xref(name:"URL", value:"https://wiki.debian.org/SSLkeys");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1571");
  script_xref(name:"URL", value:"https://github.com/g0tmi1k/debian-ssh");

  script_tag(name:"summary", value:"The remote host uses a default SSH host key that is shared among
  multiple installations.");

  script_tag(name:"impact", value:"An attacker could use this situation to compromise or eavesdrop on the SSH
  communication between the client and the server using a man-in-the-middle attack.");

  script_tag(name:"insight", value:"The list of known SSH host keys used by this plugin is a gathered from various
  sources:

  - Top 1, 000 Duplicate SSH Fingerprints on the Internet collected via the search engine Shodan in 2015.
  The most common fingerprint was found to be shared among 245.000 installations where the least common was
  still present 321 times.

  - SSH host keys generated with a vulnerable OpenSSL version on Debian and derivates (CVE-2008-0166).

  - Devices of Multiple Vendors (Cisco, ZTE, ZyXEL, OpenStage, OpenScape, TANDBERG) using hardcoded SSH host keys
  (CVE-2015-6358, CVE-2015-7255, CVE-2015-7256, CVE-2015-7276, CVE-2015-8251, CVE-2015-8260, CVE-2009-4510).");

  script_tag(name:"vuldetect", value:"Checks if the remote host responds with a known SSH host key.");

  script_tag(name:"solution", value:"Generate a new SSH host key.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("bad_ssh_host_keys.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("http_func.inc"); # For make_list_unique()

# bad_ssh_host_keys.inc might have duplicated host keys for easier
# maintenance so we will make the list here "unique" before
bad_host_keys = make_list_unique( bad_host_keys );

port = get_ssh_port( default:22 );

foreach algo( ssh_host_key_algos ) {

  host_key = get_kb_item( "SSH/" + port + "/fingerprint/" + algo );
  if( ! host_key || ! strlen( host_key ) )
    continue;

  if( in_array( search:host_key, array:bad_host_keys, part_match:FALSE ) ) {
    _report += algo + "  " + host_key + '\n';
    bhk_found = TRUE;
  }

  # Those two are workarounds as we can't include such huge lists into NASL/NVTs.
  # The greps will return something like "dd:f3:cc:a5:94:95:d3:75:45:be:26:be:1b:13:e0:05"
  # (including the double apostrophe) if a match was found.
  # nb: Make sure to update the path below if moving the includes or this NVT around.
  if( algo == "ssh-rsa" ) {
    argv = make_list( "grep", host_key, "../bad_rsa_ssh_host_keys.txt" );
    res = pread( cmd:"grep", argv:argv, cd:FALSE );
    if( res == '"' + host_key + '"' ) {
      _report += algo + "  " + host_key + '\n';
      bhk_found = TRUE;
    }
  }

  if( algo == "ssh-dss" ) {
    argv = make_list( "grep", host_key, "../bad_dsa_ssh_host_keys.txt" );
    res = pread( cmd:"grep", argv:argv, cd:FALSE );
    if( res == '"' + host_key + '"' ) {
      _report += algo + "  " + host_key + '\n';
      bhk_found = TRUE;
    }
  }
}

if( bhk_found ) {
  report = 'The following known SSH hosts key(s) were found:\n' + _report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );