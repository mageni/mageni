<x-guest-layout>
    <div class="flex min-h-screen">
        <div class="flex flex-col justify-center flex-1 px-4 py-12 sm:px-6 lg:flex-none lg:px-20 xl:px-24">
            <div class="w-full max-w-sm mx-auto lg:w-96">
                <div>
                    <svg viewBox="616.924 390.839 534.093 294.996" class="w-auto h-12" xmlns="http://www.w3.org/2000/svg">
                        <g transform="matrix(1.919993, 0, 0, 1.710266, 568.92395, 348.078705)" style="">
                            <path style="fill-opacity: 1; stroke: none; fill: rgb(81, 69, 205);" d="M 177.49050,123.22017 C 184.81453,136.25742 193.31063,146.07188 202.97884,152.66359 C 212.79308,159.10900 223.85266,162.33166 236.15762,162.33158 C 250.95230,162.33166 263.03727,157.42443 272.41258,147.60987 C 281.78729,137.64902 286.47480,124.97811 286.47511,109.59709 C 286.47480,94.802293 282.15350,82.497592 273.51121,72.682955 C 264.86833,62.868664 254.02847,57.961432 240.99161,57.961244 C 229.12610,57.961432 218.35949,62.868664 208.69174,72.682955 C 199.17001,82.351107 188.76961,99.196829 177.49050,123.22017 M 150.68381,99.709379 C 143.50589,86.818886 135.00979,77.150906 125.19547,70.705411 C 115.52734,64.260267 104.46776,61.037607 92.016692,61.037422 C 77.221638,61.037607 65.136664,65.944839 55.761733,75.759133 C 46.386643,85.427283 41.699138,97.951711 41.699203,113.33245 C 41.699138,128.12753 46.020432,140.43223 54.663098,150.24659 C 63.305607,160.06115 74.145463,164.96839 87.182697,164.96830 C 99.047834,164.96839 109.74121,160.13440 119.26284,150.46632 C 128.93068,140.79844 139.40432,123.87947 150.68381,99.709379 M 166.28443,139.91942 C 155.88383,159.84143 144.97074,174.41664 133.54510,183.64510 C 122.26563,192.87369 109.66796,197.48795 95.752051,197.48790 C 75.976520,197.48795 59.204040,189.28482 45.434563,172.87848 C 31.811432,156.47228 24.999901,136.18417 24.999949,112.01409 C 24.999901,86.379432 31.079009,65.651870 43.237293,49.831344 C 55.541927,34.011210 71.508741,26.101045 91.137784,26.100825 C 105.05370,26.101045 117.50489,30.642066 128.49138,39.723901 C 139.47757,48.659664 150.46391,63.454602 161.45043,84.108760 C 171.41120,63.894056 182.17781,49.025875 193.75030,39.504174 C 205.32237,29.836401 218.21300,25.002411 232.42226,25.002190 C 251.90445,25.002411 268.53044,33.278788 282.30030,49.831344 C 296.21602,66.384293 303.17404,86.818886 303.17436,111.13518 C 303.17404,136.62363 297.02169,157.27795 284.71729,173.09820 C 272.55877,188.77212 256.66520,196.60905 237.03653,196.60900 C 223.12024,196.60905 210.74229,192.36099 199.90266,183.86483 C 189.20907,175.22230 178.00300,160.57385 166.28443,139.91942"/>
                        </g>
                    </svg>
                    <h2 class="mt-6 text-3xl font-extrabold text-gray-900">Sign in to your account</h2>
                </div>

                <div class="mt-8">
                    <div>

                        <div class="relative mt-6">
                            <div class="absolute inset-0 flex items-center" aria-hidden="true">
                                <div class="w-full border-t border-gray-300"></div>
                            </div>
                            <div class="relative flex justify-center text-sm">
                                <span class="px-2 text-gray-500 bg-white"> <a href="{{ url('https://www.mageni.net') }}" target="_blank">Mageni Security Platform</a> </span>
                            </div>
                        </div>
                    </div>

                    <x-jet-validation-errors class="mb-4" />

                    @if (session('status'))
                        <div class="mb-4 text-sm font-medium text-green-600">
                            {{ session('status') }}
                        </div>
                    @endif

                    <div class="mt-6">
                        <form action="{{ route('login') }}" method="POST" class="space-y-6">
                            @csrf
                            <div>
                                <label for="email" class="block text-sm font-medium text-gray-700"> Email address </label>
                                <div class="mt-1">
                                    <input id="email" name="email" type="email" autocomplete="email" required autofocus :value="old('email')" class="block w-full px-3 py-2 placeholder-gray-400 border border-gray-300 rounded-md shadow-sm appearance-none focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                </div>
                            </div>

                            <div class="space-y-1">
                                <label for="password" class="block text-sm font-medium text-gray-700"> Password </label>
                                <div class="mt-1">
                                    <input id="password" name="password" type="password" autocomplete="current-password" required class="block w-full px-3 py-2 placeholder-gray-400 border border-gray-300 rounded-md shadow-sm appearance-none focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                </div>
                            </div>

                            <div class="flex items-center justify-between">
                                <div class="flex items-center">
                                    <input id="remember-me" name="remember-me" type="checkbox" class="w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500">
                                    <label for="remember-me" class="block ml-2 text-sm text-gray-900"> Remember me </label>
                                </div>

                            </div>

                            <div>
                                <button type="submit" class="flex justify-center w-full px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">Sign in</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <div class="relative flex-1 hidden w-0 lg:block">
            <img class="absolute inset-0 object-cover w-full h-full" src="https://source.unsplash.com/random/?planet" alt="">
        </div>
    </div>
</x-guest-layout>
