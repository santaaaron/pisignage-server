'use strict';

angular.module('piServerApp', [
    'ui.router',
    'ui.bootstrap',
    'ui.sortable',
    'yaru22.angular-timeago',
    'angularjs-dropdown-multiselect',
    'piConfig',
    'piIndex.controllers',
    'piGroups.controllers',
    'dashboard.controllers',
    'piAssets.controllers',
    'piAssets.services',
    'piPlayers.services',
    'piSettings.controllers',
    'piPlaylists.controllers',
    'piLabels.controllers',
    'pisignage.directives',
    'pisignage.filters',
    'pisignage.services'
])
    .config(function ($stateProvider, $urlRouterProvider, $locationProvider, $httpProvider) {

        $urlRouterProvider.otherwise('/players/players');

        $stateProvider

            .state("home", {
                abstract: true,
                url: "/",
                templateUrl: 'app/partials/menu.html',
                controller: 'IndexCtrl'

            })

            .state("home.players", {
                abstract: true,
                url: "players/",
                views: {
                    "main": {
                        templateUrl: 'app/partials/assets-main.html',
                        controller: 'ServerPlayerCtrl'
                    }
                }
            })

            .state("home.players.players", {
                url: "players?group",
                views: {
                    "left": {
                        templateUrl: '/app/partials/groups.html',
                        controller: 'GroupsCtrl'
                    },
                    "details": {
                        templateUrl: '/app/partials/group-details.html',
                        controller: 'GroupDetailCtrl'
                    },
                    "list": {
                        templateUrl: '/app/partials/players.html'
                    }
                }
            })

            .state("home.dashboard",{
                url: "dashboard",
                views: {
                    "main": {
                        templateUrl: '/app/partials/dashboard.html',
                        controller: 'DashboardCtrl'
                    }
                }
            })

            .state("home.dashboard_players", {
                url: "dashboard/players?groupName&locationName&currentPlaylist&version&bucket",
                views: {
                    "main": {
                        templateUrl: '/app/partials/players.html',
                        controller:'ServerPlayerCtrl'
                    }
                }
            })

            // .state("home.players.players_details", {
            //     url: "players/:player?group",
            //     views: {
            //         "left": {
            //             templateUrl: '/app/partials/groups.html',
            //             controller: 'GroupsCtrl'
            //         },
            //         "details": {
            //             templateUrl: '/app/partials/player-details.html',
            //             controller: 'PlayerDetailCtrl'
            //         },
            //         "list": {
            //             templateUrl: '/app/partials/group-details.html',
            //             controller: 'GroupDetailCtrl'
            //         }
            //     }
            // })
            //
            .state("home.assets", {
                abstract: true,
                url: "assets/",
                views: {
                    "main": {
                        templateUrl: 'app/partials/assets-main.html',
                        controller: 'AssetsCtrl'
                    }
                }
            })

            .state("home.assets.main", {
                url: "main",
                views: {
                    "left": {
                        templateUrl: '/app/partials/playlists.html',
                        controller: 'PlaylistsCtrl'
                    },
                    // "left2": {
                    //     templateUrl: '/app/partials/labels.html',
                    //     controller: 'LabelsCtrl'
                    // },
                    "details": {
                        templateUrl: '/app/partials/playlist-details.html',
                        controller: 'PlaylistViewCtrl'
                    },
                    "list": {
                        templateUrl: '/app/partials/assets.html',
                        controller: 'AssetsEditCtrl'
                    }
                }
            })


            .state("home.assets.assetDetails", {
                url: "detail/:file",
                views: {
                    "left": {
                        templateUrl: '/app/partials/labels.html',
                        controller: 'LabelsCtrl'
                    },
                    "list": {
                        templateUrl: '/app/partials/asset-details.html',
                        controller: 'AssetViewCtrl'
                    }
                }
            })

            .state("home.playlists", {
                abstract: true,
                url: "playlists/",
                views: {
                    "main": {
                        templateUrl: 'app/partials/playlists-main.html',
                        controller: 'AssetsCtrl'
                    }
                }
            })

            .state("home.playlists.playlistAddAssets", {
                url: "add/:playlist",
                views: {
                    "list": {
                        templateUrl: '/app/partials/assets.html',
                        controller: 'AssetsEditCtrl'
                    },
                    "right": {
                        templateUrl: '/app/partials/playlist-add.html',
                        controller: 'PlaylistAddCtrl'
                    }
                },
                data: {
                    showAllAssets: true
                }
            })

            .state("home.settings",{
                url: "settings",
                views: {
                    "main": {
                        templateUrl: '/app/partials/settings.html',
                        controller: 'SettingsCtrl'
                    }
                }
                
            })

        angular.lowercase = function(text) {             //deprectaed in 1.7.x
            return text.toLowerCase();
        }

        // Inject $window service for redirection
        $httpProvider.interceptors.push(function ($q, $rootScope, $window) {

            var onlineStatus = false;

            return {
                'response': function (response) {
                    if (!onlineStatus) {
                        onlineStatus = true;
                        $rootScope.$broadcast('onlineStatusChange', onlineStatus);
                    }
                    return response || $q.when(response);
                },

                'responseError': function (response) {
                    // Check if the error is 401 Unauthorized
                    if (response.status === 401) {
                        console.log("Received 401 Unauthorized, redirecting to login.");
                        // Perform a full page redirect to the server-side login route
                        $window.location.href = '/login';
                        // Optionally, you could broadcast an event here and handle it in controllers
                        // $rootScope.$broadcast('auth-loginRequired');
                        // return $q.reject(response); // Reject the promise if you want controllers to also know
                    } else {
                       if (onlineStatus) {
                            onlineStatus = false;
                            $rootScope.$broadcast('onlineStatusChange', onlineStatus);
                        }
                    }
                    return $q.reject(response);
                }
            };
        });

    })
    .run(function ($window,$modal,piUrls,$http, $rootScope,castApi) {
        var currentBrowser = $window.navigator.userAgent.toLowerCase();
        // if(currentBrowser.indexOf('chrome') == -1){
        //     $modal.open({
        //         template: [
        //             '<div class="modal-header">',
        //             '<h3 class="modal-title">We prefer Chrome Browser</h3>',
        //             '</div>',
        //             '<div class="modal-body">',
        //             '<p>Work in progress for making pisignage work with Firefox & Safari, ' +
        //             'please report the issues at support@pisignage.com</p>',
        //             '</div>',
        //             '<div class="modal-footer">',
        //             '<button ng-click="cancel()" class="btn btn-warning">Got it!</button>',
        //             '</div>'
        //         ].join(''),
        //         controller: ['$scope','$modalInstance',function($scope,$modalInstance){
        //             $scope.cancel = function(){
        //                     $modalInstance.close();
        //                 }
        //             }]
        //     })
        // }
        /**
         * extends string prototype object to get a string with a number of characters from a string.
         *
         * @type {Function|*}
         */
        String.prototype.trunc = String.prototype.trunc ||
            function(n){

                // this will return a substring and
                // if its larger than 'n' then truncate and append '...' to the string and return it.
                // if its less than 'n' then return the 'string'
                return this.length>n ? this.substr(0,n-1)+'...' : this.toString();
            };


        $http.get(piUrls.serverConfig)
            .success(function(data){
                if(data.success) {
                    $rootScope.serverConfig = data.data;
                    $rootScope.serverConfig.installation = $rootScope.serverConfig.installation || "local";
                } else {
                    $rootScope.serverConfig = {installation:"local"};
                }
                if (data.data.installation == "local") {
                    $modal.open({
                        template: [
                            '<div class="modal-header">',
                            '<h3 class="modal-title">Please Select your account name at pisignage.com</h3>',
                            '</div>',
                            '<div class="modal-body">',
                            '<input class="form-control" type="text", name="user" ng-model="serverConfig.installation", required="">',
                            '</div>',
                            '<div class="modal-footer">',
                            '<button ng-click="save()" class="btn btn-warning">Save</button>',
                            '</div>'
                        ].join(''),
                        controller: ['$scope','$modalInstance',function($scope,$modalInstance){
                            $scope.save = function(){
                                $http.post(piUrls.settings, $rootScope.serverConfig)
                                    .success(function(data, status) {
                                        if (data.success) {
                                        }
                                        setTimeout(window.location.reload.bind(window.location), 2000);
                                    })
                                    .error(function(data, status) {
                                    });
                                $modalInstance.close();
                            }
                        }]
                    })
                }

            }).error(function(err){
                console.log(err);
                $rootScope.serverConfig = {installation:"local"};
            })

        castApi.init();
    });