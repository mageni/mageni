###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201301-01.nasl 12128 2018-10-26 13:35:25Z cfischer $
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.121000");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:25:19 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201301-01");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Mozilla Firefox, Thunderbird, SeaMonkey, NSS, GNU IceCat, and XULRunner. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201301-01");
  script_cve_id("CVE-2011-3101", "CVE-2007-2436", "CVE-2007-2437", "CVE-2007-2671", "CVE-2007-3073", "CVE-2008-0016", "CVE-2008-0017", "CVE-2008-0367", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4070", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513", "CVE-2008-5822", "CVE-2008-5913", "CVE-2008-6961", "CVE-2009-0071", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777", "CVE-2009-1044", "CVE-2009-1169", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312", "CVE-2009-1313", "CVE-2009-1392", "CVE-2009-1563", "CVE-2009-1571", "CVE-2009-1828", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-2043", "CVE-2009-2044", "CVE-2009-2061", "CVE-2009-2065", "CVE-2009-2210", "CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2470", "CVE-2009-2471", "CVE-2009-2472", "CVE-2009-2477", "CVE-2009-2478", "CVE-2009-2479", "CVE-2009-2535", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2664", "CVE-2009-2665", "CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079", "CVE-2009-3274", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3377", "CVE-2009-3378", "CVE-2009-3379", "CVE-2009-3380", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383", "CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3555", "CVE-2009-3978", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3987", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162", "CVE-2010-0163", "CVE-2010-0164", "CVE-2010-0165", "CVE-2010-0166", "CVE-2010-0167", "CVE-2010-0168", "CVE-2010-0169", "CVE-2010-0170", "CVE-2010-0171", "CVE-2010-0172", "CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182", "CVE-2010-0183", "CVE-2010-0220", "CVE-2010-0648", "CVE-2010-0654", "CVE-2010-1028", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-1585", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754", "CVE-2010-2755", "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3131", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169", "CVE-2010-3170", "CVE-2010-3171", "CVE-2010-3173", "CVE-2010-3174", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183", "CVE-2010-3399", "CVE-2010-3400", "CVE-2010-3765", "CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778", "CVE-2010-4508", "CVE-2010-5074", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062", "CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0068", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0076", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0079", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-0082", "CVE-2011-0083", "CVE-2011-0084", "CVE-2011-0085", "CVE-2011-1187", "CVE-2011-1202", "CVE-2011-1712", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2369", "CVE-2011-2370", "CVE-2011-2371", "CVE-2011-2372", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377", "CVE-2011-2378", "CVE-2011-2605", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984", "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2993", "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2997", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3004", "CVE-2011-3005", "CVE-2011-3026", "CVE-2011-3062", "CVE-2011-3232", "CVE-2011-3389", "CVE-2011-3640", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3649", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3653", "CVE-2011-3654", "CVE-2011-3655", "CVE-2011-3658", "CVE-2011-3659", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665", "CVE-2011-3670", "CVE-2011-3866", "CVE-2011-4688", "CVE-2012-0441", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450", "CVE-2012-0451", "CVE-2012-0452", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947", "CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1956", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-1994", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3977", "CVE-2012-3978", "CVE-2012-3980", "CVE-2012-3982", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4190", "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193", "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196", "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4206", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4212", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5354", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201301-01");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-client/firefox", unaffected: make_list("ge 10.0.11"), vulnerable: make_list("lt 10.0.11"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/firefox-bin", unaffected: make_list("ge 10.0.11"), vulnerable: make_list("lt 10.0.11"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/thunderbird", unaffected: make_list("ge 10.0.11"), vulnerable: make_list("lt 10.0.11"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/thunderbird-bin", unaffected: make_list("ge 10.0.11"), vulnerable: make_list("lt 10.0.11"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 2.14-r1"), vulnerable: make_list("lt 2.14-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 2.14"), vulnerable: make_list("lt 2.14"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-libs/nss", unaffected: make_list("ge 3.14"), vulnerable: make_list("lt 3.14"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list(), vulnerable: make_list("lt 3.6.8"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list(), vulnerable: make_list("lt 3.5.6"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list(), vulnerable: make_list("lt 3.0.4-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list(), vulnerable: make_list("lt 3.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"www-client/icecat", unaffected: make_list(), vulnerable: make_list("lt 10.0-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-libs/xulrunner", unaffected: make_list(), vulnerable: make_list("lt 2.0-r1"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"net-libs/xulrunner-bin", unaffected: make_list(), vulnerable: make_list("lt 1.8.1.19"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
