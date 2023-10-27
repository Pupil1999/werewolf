// The 'werewolf' program.
program werewolf.aleo {
    // Ciphertext produced by ElgamalCipher, a tuple of two group elements
    struct ElgamalCipher {
        c1: group,
        c2: group,
    }

    // Each player will sample a public key for shuffling,
    // the link between the key and the player is hidden
    // All the inputs are public, since they are the
    // encryption of pks from the players
    transition elgamal_key_gen(sk: scalar) -> group {
        return sk * group::GEN;
    }

    // Sum up the public keys in the beginning
    transition aggregate_public_keys(
        public pk1: group,
        public pk2: group,
        public pk3: group,
        public pk4: group,
        public pk5: group,
        public pk6: group,
        public pk7: group,
        public pk8: group,
        public pk9: group,
        public pk10: group,
        public pk11: group,
        public pk12: group
        ) -> group {
        return pk1+pk2+pk3+pk4+pk5+pk6+pk7+pk8+pk9+pk10+pk11+pk12;
    }
    transition dec_public_key(
        public pre: group,
        public dead: group
    ) -> group {
        return pre - dead;
    }

    // Encrypt the public role keys for shuffling.
    transition elgamal_enc(rpk: group, pk: group, r: scalar) -> ElgamalCipher {
        let c1: group = r * group::GEN;
        let c2: group = r * pk + rpk;
        return ElgamalCipher {
            c1,
            c2
        };
    }

    // 
    transition gen_role_list(
        public role_1: ElgamalCipher,
        public role_2: ElgamalCipher,
        public role_3: ElgamalCipher,
        public role_4: ElgamalCipher,
        public role_5: ElgamalCipher,
        public role_6: ElgamalCipher,
        public role_7: ElgamalCipher,
        public role_8: ElgamalCipher,
        public role_9: ElgamalCipher,
        public role_10: ElgamalCipher,
        public role_11: ElgamalCipher,
        public role_12: ElgamalCipher
    ) -> RoleList {
        return RoleList {
            l1: ElgamalCipher {
                c1: role_1.c1,
                c2: role_1.c2
            },
            l2: ElgamalCipher {
                c1: role_2.c1,
                c2: role_2.c2
            },
            l3: ElgamalCipher {
                c1: role_3.c1,
                c2: role_3.c2
            },
            l4: ElgamalCipher {
                c1: role_4.c1,
                c2: role_4.c2
            },
            l5: ElgamalCipher {
                c1: role_5.c1,
                c2: role_5.c2
            },
            l6: ElgamalCipher {
                c1: role_6.c1,
                c2: role_6.c2
            },
            l7: ElgamalCipher {
                c1: role_7.c1,
                c2: role_7.c2
            },
            l8: ElgamalCipher {
                c1: role_8.c1,
                c2: role_8.c2
            },
            l9: ElgamalCipher {
                c1: role_9.c1,
                c2: role_9.c2
            },
            l10: ElgamalCipher {
                c1: role_10.c1,
                c2: role_10.c2
            },
            l11: ElgamalCipher {
                c1: role_11.c1,
                c2: role_11.c2
            },
            l12: ElgamalCipher {
                c1: role_12.c1,
                c2: role_12.c2
            }
        };
    }

    // There is supposed to be 12 players in each game
    // 4 - Villagers, 4 - Wolves, 1 - Witch, Seer, Protector, Hunter
    struct RoleList {
        l1: ElgamalCipher,
        l2: ElgamalCipher,
        l3: ElgamalCipher,
        l4: ElgamalCipher,
        l5: ElgamalCipher,
        l6: ElgamalCipher,
        l7: ElgamalCipher,
        l8: ElgamalCipher,
        l9: ElgamalCipher,
        l10: ElgamalCipher,
        l11: ElgamalCipher,
        l12: ElgamalCipher
    }

    struct Permutation {
        p1: u8,
        p2: u8,
        p3: u8,
        p4: u8,
        p5: u8,
        p6: u8,
        p7: u8,
        p8: u8,
        p9: u8,
        p10: u8,
        p11: u8,
        p12: u8
    }

    // Generate 12 permutation arguments for shuffle
    transition prod_perm(
        p1: u8,
        p2: u8,
        p3: u8,
        p4: u8,
        p5: u8,
        p6: u8,
        p7: u8,
        p8: u8,
        p9: u8,
        p10: u8,
        p11: u8,
        p12: u8
    ) -> Permutation {
        assert(p1 >= 1u8 && p1 <= 12u8);
        assert(p2 >= 1u8 && p2 <= 12u8);
        assert(p3 >= 1u8 && p3 <= 12u8);
        assert(p4 >= 1u8 && p4 <= 12u8);
        assert(p5 >= 1u8 && p5 <= 12u8);
        assert(p6 >= 1u8 && p6 <= 12u8);
        assert(p7 >= 1u8 && p7 <= 12u8);
        assert(p8 >= 1u8 && p8 <= 12u8);
        assert(p9 >= 1u8 && p9 <= 12u8);
        assert(p10 >= 1u8 && p10 <= 12u8);
        assert(p11 >= 1u8 && p11 <= 12u8);
        assert(p12 >= 1u8 && p12 <= 12u8);
        assert(p1 != p2);assert(p1 != p3);assert(p1 != p4);assert(p1 != p5);
        assert(p1 != p6);assert(p1 != p7);assert(p1 != p8);assert(p1 != p9);
        assert(p1 != p10);assert(p1 != p11);assert(p1 != p12);assert(p2 != p3);
        assert(p2 != p4);assert(p2 != p5);assert(p2 != p6);assert(p2 != p7);
        assert(p2 != p8);assert(p2 != p9);assert(p2 != p10);assert(p2 != p11);
        assert(p2 != p12);assert(p3 != p4);assert(p3 != p5);assert(p3 != p6);
        assert(p3 != p7);assert(p3 != p8);assert(p3 != p9);assert(p3 != p10);
        assert(p3 != p11);assert(p3 != p12);assert(p4 != p5);assert(p4 != p6);
        assert(p4 != p7);assert(p4 != p8);assert(p4 != p9);assert(p4 != p10);
        assert(p4 != p11);assert(p4 != p12);assert(p5 != p6);assert(p5 != p7);
        assert(p5 != p8);assert(p5 != p9);assert(p5 != p10);assert(p5 != p11);
        assert(p5 != p12);assert(p6 != p7);assert(p6 != p8);assert(p6 != p9);
        assert(p6 != p10);assert(p6 != p11);assert(p6 != p12);assert(p7 != p8);
        assert(p7 != p9);assert(p7 != p10);assert(p7 != p11);assert(p7 != p12);
        assert(p8 != p9);assert(p8 != p10);assert(p8 != p11);assert(p8 != p12);
        assert(p9 != p10);assert(p9 != p11);assert(p9 != p12);assert(p10 != p11);
        assert(p10 != p12);assert(p11 != p12);

        return Permutation {
            p1: p1,
            p2: p2,
            p3: p3,
            p4: p4,
            p5: p5,
            p6: p6,
            p7: p7,
            p8: p8,
            p9: p9,
            p10: p10,
            p11: p11,
            p12: p12,
        };
    }

    inline resort(
        list: RoleList,
        index: u8
    ) -> ElgamalCipher {
        if(index == 1u8) {
            return list.l1;
        } else if(index == 2u8) {
            return list.l2;
        } else if(index == 3u8) {
            return list.l3;
        } else if(index == 4u8) {
            return list.l4;
        } else if(index == 5u8) {
            return list.l5;
        } else if(index == 6u8) {
            return list.l6;
        } else if(index == 7u8) {
            return list.l7;
        } else if(index == 8u8) {
            return list.l8;
        } else if(index == 9u8) {
            return list.l9;
        } else if(index == 10u8) {
            return list.l10;
        } else if(index == 11u8) {
            return list.l11;
        } else {
            return list.l12;
        }
    }

    // Rerandomize the list and permutate it.
    transition shuffle(
        public prelist: RoleList,
        public pk: group,
        // perm: Permutation,
        r1: scalar,
        r2: scalar,
        r3: scalar,
        r4: scalar,
        r5: scalar,
        r6: scalar,
        r7: scalar,
        r8: scalar,
        r9: scalar,
        r10:scalar,
        r11:scalar,
        r12:scalar
    ) -> RoleList {
        let cc1: ElgamalCipher = ElgamalCipher {
            c1: prelist.l1.c1 + r1 * group::GEN,
            c2: prelist.l1.c2 + r1 * pk,
        };
        let cc2: ElgamalCipher = ElgamalCipher {
            c1: prelist.l2.c1 + r2 * group::GEN,
            c2: prelist.l2.c2 + r2 * pk,
        };
        let cc3: ElgamalCipher = ElgamalCipher {
            c1: prelist.l3.c1 + r3 * group::GEN,
            c2: prelist.l3.c2 + r3 * pk,
        };
        let cc4: ElgamalCipher = ElgamalCipher {
            c1: prelist.l4.c1 + r4 * group::GEN,
            c2: prelist.l4.c2 + r4 * pk,
        };
        let cc5: ElgamalCipher = ElgamalCipher {
            c1: prelist.l5.c1 + r5 * group::GEN,
            c2: prelist.l5.c2 + r5 * pk,
        };
        let cc6: ElgamalCipher = ElgamalCipher {
            c1: prelist.l6.c1 + r6 * group::GEN,
            c2: prelist.l6.c2 + r6 * pk,
        };
        let cc7: ElgamalCipher = ElgamalCipher {
            c1: prelist.l7.c1 + r7 * group::GEN,
            c2: prelist.l7.c2 + r7 * pk,
        };
        let cc8: ElgamalCipher = ElgamalCipher {
            c1: prelist.l8.c1 + r8 * group::GEN,
            c2: prelist.l8.c2 + r8 * pk,
        };
        let cc9: ElgamalCipher = ElgamalCipher {
            c1: prelist.l9.c1 + r9 * group::GEN,
            c2: prelist.l9.c2 + r9 * pk,
        };
        let cc10: ElgamalCipher = ElgamalCipher {
            c1: prelist.l10.c1 + r10 * group::GEN,
            c2: prelist.l10.c2 + r10 * pk,
        };
        let cc11: ElgamalCipher = ElgamalCipher {
            c1: prelist.l11.c1 + r11 * group::GEN,
            c2: prelist.l11.c2 + r11 * pk,
        };
        let cc12: ElgamalCipher = ElgamalCipher {
            c1: prelist.l12.c1 + r12 * group::GEN,
            c2: prelist.l12.c2 + r12 * pk,
        };

        let list: RoleList = RoleList {
            l1: cc1,
            l2: cc2,
            l3: cc3,
            l4: cc4,
            l5: cc5,
            l6: cc6,
            l7: cc7,
            l8: cc8,
            l9: cc9,
            l10:cc10,
            l11:cc11,
            l12:cc12,
        };/*
        By now, Aleo is still under intensive construction,
        it cannot compile so many instructions into .aleo file,
        so we just comment these permutation and do the
        permutation in our python parser since the permutation
        will produce 1500 instructions
        // Permutate the list in the encrypted list
        let l1: ElgamalCipher = resort(list, perm.p1);
        let l2: ElgamalCipher = resort(list, perm.p2);
        let l3: ElgamalCipher = resort(list, perm.p3);
        let l4: ElgamalCipher = resort(list, perm.p4);
        let l5: ElgamalCipher = resort(list, perm.p5);
        let l6: ElgamalCipher = resort(list, perm.p6);
        let l7: ElgamalCipher = resort(list, perm.p7);
        let l8: ElgamalCipher = resort(list, perm.p8);
        let l9: ElgamalCipher = resort(list, perm.p9);
        let l10: ElgamalCipher = resort(list, perm.p10);
        let l11: ElgamalCipher = resort(list, perm.p11);
        let l12: ElgamalCipher = resort(list, perm.p12);
        return RoleList {
            l1: l1,
            l2: l2,
            l3: l3,
            l4: l4,
            l5: l5,
            l6: l6,
            l7: l7,
            l8: l8,
            l9: l9,
            l10: l10,
            l11: l11,
            l12: l12
        };*/
        
        return list;
    }

    transition dec_shuffled_list(
        public list: RoleList,
        psk: scalar,
    ) -> RoleList {
        let r1: ElgamalCipher = ElgamalCipher {
            c1: list.l1.c1,
            c2: list.l1.c2 - list.l1.c1 * psk
        };
        let r2: ElgamalCipher = ElgamalCipher {
            c1: list.l2.c1,
            c2: list.l2.c2 - list.l2.c1 * psk
        };
        let r3: ElgamalCipher = ElgamalCipher {
            c1: list.l3.c1,
            c2: list.l3.c2 - list.l3.c1 * psk
        };
        let r4: ElgamalCipher = ElgamalCipher {
            c1: list.l4.c1,
            c2: list.l4.c2 - list.l4.c1 * psk
        };
        let r5: ElgamalCipher = ElgamalCipher {
            c1: list.l5.c1,
            c2: list.l5.c2 - list.l5.c1 * psk
        };
        let r6: ElgamalCipher = ElgamalCipher {
            c1: list.l6.c1,
            c2: list.l6.c2 - list.l6.c1 * psk
        };
        let r7: ElgamalCipher = ElgamalCipher {
            c1: list.l7.c1,
            c2: list.l7.c2 - list.l7.c1 * psk
        };
        let r8: ElgamalCipher = ElgamalCipher {
            c1: list.l8.c1,
            c2: list.l8.c2 - list.l8.c1 * psk
        };
        let r9: ElgamalCipher = ElgamalCipher {
            c1: list.l9.c1,
            c2: list.l9.c2 - list.l9.c1 * psk
        };
        let r10: ElgamalCipher = ElgamalCipher {
            c1: list.l10.c1,
            c2: list.l10.c2 - list.l10.c1 * psk
        };
        let r11: ElgamalCipher = ElgamalCipher {
            c1: list.l11.c1,
            c2: list.l11.c2 - list.l11.c1 * psk
        };
        let r12: ElgamalCipher = ElgamalCipher {
            c1: list.l12.c1,
            c2: list.l12.c2 - list.l12.c1 * psk
        };

        return RoleList {
            l1: r1,
            l2: r2,
            l3: r3,
            l4: r4,
            l5: r5,
            l6: r6,
            l7: r7,
            l8: r8,
            l9: r9,
            l10: r10,
            l11: r11,
            l12: r12,
        };
    }

    struct PublicRoleKeys{
        wolf1: group,
        wolf2: group,
        wolf3: group,
        wolf4: group,
        villager1: group,
        villager2: group,
        villager3: group,
        villager4: group,
        seer: group,
        witch: group,
        hunter: group,
        protector: group
    }
    struct SurvivorCipher{
        wolf: ElgamalCipher,
        villager: ElgamalCipher,
        psychic: ElgamalCipher
    }
    transition gen_public_role_keys_list(
        wolf1: group, 
        wolf2: group,
        wolf3: group,
        wolf4: group,
        villager1: group,
        villager2: group,
        villager3: group,
        villager4: group,
        seer: group,
        witch: group,
        hunter: group,
        protector: group
        ) -> PublicRoleKeys {
        return PublicRoleKeys{
            wolf1: wolf1,
            wolf2: wolf2,
            wolf3: wolf3,
            wolf4: wolf4,
            villager1: villager1,
            villager2: villager2,
            villager3: villager3,
            villager4: villager4,
            seer: seer,
            witch: witch,
            hunter: hunter,
            protector: protector
        };
    }

    transition statistic_init() -> SurvivorCipher {
        let c_0: ElgamalCipher = ElgamalCipher {
            c1: 0group,
            c2: 0group
        };
        return SurvivorCipher {
            wolf: c_0,
            villager: c_0,
            psychic: c_0
        };
    }

    transition statistic_survivors(
        public enc: bool,
        rsk: scalar, 
        public rpks: PublicRoleKeys,
        r: scalar,   // a random number used to indicate survivors
        er_1: scalar, // a random number used in elgamal encryption
        er_2: scalar,
        er_3: scalar,
        public pk: group,
        psk: scalar,
        public pre_cipher: SurvivorCipher
        ) -> SurvivorCipher {
        if(enc){
            let rpk: group = rsk * group::GEN;
            if( rpk == rpks.wolf1 ||
                rpk == rpks.wolf2 ||
                rpk == rpks.wolf3 ||
                rpk == rpks.wolf4){
                return SurvivorCipher {
                    wolf: ElgamalCipher {
                        c1: pre_cipher.wolf.c1 + er_1*group::GEN,
                        c2: pre_cipher.wolf.c2 + er_1*pk + r*group::GEN
                    },
                    villager: ElgamalCipher {
                        c1: pre_cipher.villager.c1 + er_2*group::GEN,
                        c2: pre_cipher.villager.c2 + er_2*pk
                    },
                    psychic: ElgamalCipher {
                        c1: pre_cipher.psychic.c1 + er_3*group::GEN,
                        c2: pre_cipher.psychic.c2 + er_3*pk
                    },
                };
            } else if( 
                rpk == rpks.villager1 ||
                rpk == rpks.villager2 ||
                rpk == rpks.villager3 ||
                rpk == rpks.villager4){
                return SurvivorCipher {
                    wolf: ElgamalCipher {
                        c1: pre_cipher.wolf.c1 + er_1*group::GEN,
                        c2: pre_cipher.wolf.c2 + er_1*pk
                    },
                    villager: ElgamalCipher {
                        c1: pre_cipher.villager.c1 + er_2*group::GEN,
                        c2: pre_cipher.villager.c2 + er_2*pk + r*group::GEN
                    },
                    psychic: ElgamalCipher {
                        c1: pre_cipher.psychic.c1 + er_3*group::GEN,
                        c2: pre_cipher.psychic.c2 + er_3*pk
                    },
                };
            } else {
                return SurvivorCipher {
                    wolf: ElgamalCipher {
                        c1: pre_cipher.wolf.c1 + er_1*group::GEN,
                        c2: pre_cipher.wolf.c2 + er_1*pk
                    },
                    villager: ElgamalCipher {
                        c1: pre_cipher.villager.c1 + er_2*group::GEN,
                        c2: pre_cipher.villager.c2 + er_2*pk
                    },
                    psychic: ElgamalCipher {
                        c1: pre_cipher.psychic.c1 + er_3*group::GEN,
                        c2: pre_cipher.psychic.c2 + er_3*pk + r*group::GEN
                    },
                };
            }
        } else {
            return SurvivorCipher {
                wolf: ElgamalCipher {
                        c1: pre_cipher.wolf.c1,
                        c2: pre_cipher.wolf.c2 - pre_cipher.wolf.c1 * psk
                    },
                    villager: ElgamalCipher {
                        c1: pre_cipher.villager.c1,
                        c2: pre_cipher.villager.c2 - pre_cipher.villager.c1 * psk
                    },
                    psychic: ElgamalCipher {
                        c1: pre_cipher.psychic.c1,
                        c2: pre_cipher.psychic.c2 - pre_cipher.psychic.c1 * psk
                    },
            };
        }
    }

    struct CheckRoleList{
        p1: ElgamalCipher,
        p2: ElgamalCipher,
        p3: ElgamalCipher,
        p4: ElgamalCipher,
        p5: ElgamalCipher,
        p6: ElgamalCipher,
        p7: ElgamalCipher,
        p8: ElgamalCipher,
        p9: ElgamalCipher,
        p10: ElgamalCipher,
        p11: ElgamalCipher,
        p12: ElgamalCipher,
    }
    transition check_role_init(
        m1: scalar,
        m2: scalar,
        m3: scalar,
        m4: scalar,
        m5: scalar,
        m6: scalar,
        m7: scalar,
        m8: scalar,
        m9: scalar,
        m10: scalar,
        m11: scalar,
        m12: scalar
        ) -> CheckRoleList {
        return CheckRoleList {
            p1: ElgamalCipher {
                c1: 0group,
                c2: m1 * group::GEN
            },
            p2: ElgamalCipher {
                c1: 0group,
                c2: m2 * group::GEN
            },
            p3: ElgamalCipher {
                c1: 0group,
                c2: m3 * group::GEN
            },
            p4: ElgamalCipher {
                c1: 0group,
                c2: m4 * group::GEN
            },
            p5: ElgamalCipher {
                c1: 0group,
                c2: m5 * group::GEN
            },
            p6: ElgamalCipher {
                c1: 0group,
                c2: m6 * group::GEN
            },
            p7: ElgamalCipher {
                c1: 0group,
                c2: m7 * group::GEN
            },
            p8: ElgamalCipher {
                c1: 0group,
                c2: m8 * group::GEN
            },
            p9: ElgamalCipher {
                c1: 0group,
                c2: m9 * group::GEN
            },
            p10: ElgamalCipher {
                c1: 0group,
                c2: m10 * group::GEN
            },
            p11: ElgamalCipher {
                c1: 0group,
                c2: m11 * group::GEN
            },
            p12: ElgamalCipher {
                c1: 0group,
                c2: m12 * group::GEN
            }
        };
    }

    inline ckrd_selct(
        ind: u8, 
        comp: u8, 
        c1: ElgamalCipher, 
        c2: ElgamalCipher
        ) -> ElgamalCipher {
        if(ind == comp){
            return c1;
        } else {
            return c2;
        }
    }
    inline emb_selct(
        ind: u8,
        comp: u8,
        p: ElgamalCipher,
        r: scalar,
        rsk: scalar,
        rpks: PublicRoleKeys
    ) -> ElgamalCipher {
        if(ind != comp){
            return p;
        } else {
            if( rsk * group::GEN == rpks.wolf1 ||
                rsk * group::GEN == rpks.wolf2 ||
                rsk * group::GEN == rpks.wolf3 ||
                rsk * group::GEN == rpks.wolf4 ){
                return ElgamalCipher {
                    c1: p.c1 * r,
                    c2: p.c2 * r + group::GEN
                };
            } else {
                return ElgamalCipher {
                    c1: p.c1 * r,
                    c2: p.c2 * r
                };
            }
        }
    }
    struct TwelveRand {
        r1: scalar,
        r2: scalar,
        r3: scalar,
        r4: scalar,
        r5: scalar,
        r6: scalar,
        r7: scalar,
        r8: scalar,
        r9: scalar,
        r10: scalar,
        r11: scalar,
        r12: scalar,
    }
    transition gen_twelve_rands(
        r1: scalar,
        r2: scalar,
        r3: scalar,
        r4: scalar,
        r5: scalar,
        r6: scalar,
        r7: scalar,
        r8: scalar,
        r9: scalar,
        r10: scalar,
        r11: scalar,
        r12: scalar,
    ) -> TwelveRand {
        return TwelveRand {
            r1: r1, r2: r2, r3: r3, r4: r4, r5: r5, r6: r6,
            r7: r7, r8: r8, r9: r9, r10: r10, r11: r11, r12: r12,
        };
    }

    transition rerand(
        rand: bool, // rerand or decrypting?
        public rpks: PublicRoleKeys, // used to constrain the behaviour
        rsk: scalar, // the secret role key of this player
        ch: u8, // The choice from seer to check the role of some player
        public list: CheckRoleList, // ciphers
        rands: TwelveRand, // used for elgamal encryption
        r: scalar, // used to embed a trapdoor in cipher
        public inx: u8, // Index when embedding roles into choices' ciphers
        emdr: scalar // 
        ) -> CheckRoleList {

        assert( ch >= 1u8 && ch <= 12u8);
        if(rand){
            let rc1: ElgamalCipher = ElgamalCipher {
                c1: list.p1.c1 + group::GEN * rands.r1,
                c2: list.p1.c2 + rpks.seer * rands.r1
            };
            let rc2: ElgamalCipher = ElgamalCipher {
                c1: list.p2.c1 + group::GEN * rands.r2,
                c2: list.p2.c2 + rpks.seer * rands.r2
            };
            let rc3: ElgamalCipher = ElgamalCipher {
                c1: list.p3.c1 + group::GEN * rands.r3,
                c2: list.p3.c2 + rpks.seer * rands.r3
            };
            let rc4: ElgamalCipher = ElgamalCipher {
                c1: list.p4.c1 + group::GEN * rands.r4,
                c2: list.p4.c2 + rpks.seer * rands.r4
            };
            let rc5: ElgamalCipher = ElgamalCipher {
                c1: list.p5.c1 + group::GEN * rands.r5,
                c2: list.p5.c2 + rpks.seer * rands.r5
            };
            let rc6: ElgamalCipher = ElgamalCipher {
                c1: list.p6.c1 + group::GEN * rands.r6,
                c2: list.p6.c2 + rpks.seer * rands.r6
            };
            let rc7: ElgamalCipher = ElgamalCipher {
                c1: list.p7.c1 + group::GEN * rands.r7,
                c2: list.p7.c2 + rpks.seer * rands.r7
            };
            let rc8: ElgamalCipher = ElgamalCipher {
                c1: list.p8.c1 + group::GEN * rands.r8,
                c2: list.p8.c2 + rpks.seer * rands.r8
            };
            let rc9: ElgamalCipher = ElgamalCipher {
                c1: list.p9.c1 + group::GEN * rands.r9,
                c2: list.p9.c2 + rpks.seer * rands.r9
            };
            let rc10: ElgamalCipher = ElgamalCipher {
                c1: list.p10.c1 + group::GEN * rands.r10,
                c2: list.p10.c2 + rpks.seer * rands.r10
            };
            let rc11: ElgamalCipher = ElgamalCipher {
                c1: list.p11.c1 + group::GEN * rands.r11,
                c2: list.p11.c2 + rpks.seer * rands.r11
            };
            let rc12: ElgamalCipher = ElgamalCipher {
                c1: list.p12.c1 + group::GEN * rands.r12,
                c2: list.p12.c2 + rpks.seer * rands.r12
            };

            let rch: ElgamalCipher = ElgamalCipher {
                c1: group::GEN * r,
                c2: rpks.seer * r
            };

            if(rsk * group::GEN == rpks.seer){
                return CheckRoleList { // The seer can put a trapdoor in it.
                    p1: ckrd_selct(ch, 1u8, rch, rc1),
                    p2: ckrd_selct(ch, 2u8, rch, rc2),
                    p3: ckrd_selct(ch, 3u8, rch, rc3),
                    p4: ckrd_selct(ch, 4u8, rch, rc4),
                    p5: ckrd_selct(ch, 5u8, rch, rc5),
                    p6: ckrd_selct(ch, 6u8, rch, rc6),
                    p7: ckrd_selct(ch, 7u8, rch, rc7),
                    p8: ckrd_selct(ch, 8u8, rch, rc8),
                    p9: ckrd_selct(ch, 9u8, rch, rc9),
                    p10: ckrd_selct(ch, 10u8, rch, rc10),
                    p11: ckrd_selct(ch, 11u8, rch, rc11),
                    p12: ckrd_selct(ch, 12u8, rch, rc12),
                };
            } else {
                return CheckRoleList { // Other players just re-randomize this table
                    p1: rc1, p2: rc2, p3: rc3, p4: rc4, p5: rc5, p6: rc6, p7: rc7,
                    p8: rc8, p9: rc9, p10: rc10, p11: rc11, p12: rc12,
                };
            }
        } else { // if the function is in embedding phase
            return CheckRoleList {
                p1: emb_selct(inx, 1u8, list.p1, emdr, rsk, rpks),
                p2: emb_selct(inx, 2u8, list.p2, emdr, rsk, rpks),
                p3: emb_selct(inx, 3u8, list.p3, emdr, rsk, rpks),
                p4: emb_selct(inx, 4u8, list.p4, emdr, rsk, rpks),
                p5: emb_selct(inx, 5u8, list.p5, emdr, rsk, rpks),
                p6: emb_selct(inx, 6u8, list.p6, emdr, rsk, rpks),
                p7: emb_selct(inx, 7u8, list.p7, emdr, rsk, rpks),
                p8: emb_selct(inx, 8u8, list.p8, emdr, rsk, rpks),
                p9: emb_selct(inx, 9u8, list.p9, emdr, rsk, rpks),
                p10: emb_selct(inx, 10u8, list.p10, emdr, rsk, rpks),
                p11: emb_selct(inx, 11u8, list.p11, emdr, rsk, rpks),
                p12: emb_selct(inx, 12u8, list.p12, emdr, rsk, rpks),
            };
        }
    }
    
    // No need to verify this transition on-chain, 
    // just call by seer for decryption
    transition dec_check_role(
        rsk: scalar,
        c: ElgamalCipher
        ) -> bool {
        let plaintext: group = c.c2 - c.c1 * rsk;
        return plaintext == group::GEN;
    }

    struct KillCipher {
        kc1: ElgamalCipher, // will encrypt the victim
        kc2: ElgamalCipher, // will encrypt the protected role
        kc3: ElgamalCipher  // will encrypt the victim with witch' public key
    }
    transition kill_init() -> KillCipher {
        return KillCipher {
            kc1: ElgamalCipher{ c1: 0group, c2: 0group },
            kc2: ElgamalCipher{ c1: 0group, c2: 0group },
            kc3: ElgamalCipher{ c1: 0group, c2: 0group },
        };
    }

    transition kill_vote(
        public pk: group, // the aggregated public key for encryption
        rsk: scalar, // the secret of voter
        ppk_v: group, // the public key of the victim
        ppk_p: group, // the public key of the protected player
        rpks: PublicRoleKeys, // used to constrain the behaviour
        rpk_wolf: group, // the public key of the wolf who can kill people
        er1: scalar, // rnd for elgamal encryption
        er2: scalar, // rnd for elgamal encryption
        er3: scalar, // rnd for elgamal encryption
        public rpk_witch: group, // encrypt with witch's public key
        public pre: KillCipher // the cipher of the last round
    ) -> KillCipher {
        let kc1: ElgamalCipher = ElgamalCipher {
            c1: pre.kc1.c1 + group::GEN * er1,
            c2: pre.kc1.c2 + pk * er1
        };

        let kc2: ElgamalCipher = ElgamalCipher {
            c1: pre.kc2.c1 + group::GEN * er2,
            c2: pre.kc2.c2 + pk * er2
        };
        if(rsk * group::GEN == rpks.protector) {
            kc2 = ElgamalCipher {
                c1: kc2.c1,
                c2: kc2.c2 + ppk_p
            };
        }

        let kc3: ElgamalCipher = ElgamalCipher {
            c1: pre.kc3.c1 + group::GEN * er3,
            c2: pre.kc3.c2 + pk * er3 + rpk_witch * er3
        };
        if(rsk * group::GEN == rpk_wolf) {
            kc1 = ElgamalCipher {
                c1: kc1.c1,
                c2: kc1.c2 + ppk_v
            };
            kc3 = ElgamalCipher {
                c1: kc3.c1,
                c2: kc3.c2 + ppk_v
            };
        }

        return KillCipher {
            kc1: kc1,
            kc2: kc2,
            kc3: kc3
        };
    }

    transition dec_kill_vote(
        public pre: KillCipher, // 3 rows for game killing
        psk: scalar,
        public dec_ch: u8,
        public init: bool, // if true, just sub the second row with the first row
        r: scalar, // used to raise the entropy for testing
        rsk: scalar, // secret role key of witch
        public rpk_witch: group,
        save: bool, // whether the witch decides to save the victim
        public pk_: group, // intermediate public key in decryption
    ) -> KillCipher {
        assert( dec_ch >= 1u8 && dec_ch <= 4u8);
        if(init){
            return KillCipher {
                kc1: pre.kc1,
                kc2: ElgamalCipher {
                    c1: pre.kc2.c1 - pre.kc1.c1,
                    c2: pre.kc2.c2 - pre.kc1.c2
                },
                kc3: pre.kc3
            };
        } else {
            if(dec_ch == 1u8){ // decrypt the first row
                // the witch can save the player
                if(rsk * group::GEN == rpk_witch && save){
                    return KillCipher {
                        kc1: ElgamalCipher{
                            c1: pre.kc1.c1,
                            c2: pk_ * r
                        },
                        kc2: pre.kc2,
                        kc3: pre.kc3
                    };
                } else { //
                    return KillCipher {
                        kc1: ElgamalCipher{
                            c1: pre.kc1.c1,
                            c2: pre.kc1.c2 - pre.kc1.c1 * psk
                        },
                        kc2: pre.kc2,
                        kc3: pre.kc3
                    };
                }
            } else if(dec_ch == 2u8){ // raise the entropy of the second row
                return KillCipher {
                    kc1: pre.kc1,
                    kc2: ElgamalCipher{
                        c1: pre.kc2.c1 * r,
                        c2: pre.kc2.c2 * r
                    },
                    kc3: pre.kc3
                };
            } else if(dec_ch == 3u8){ // decrypt the second row
                return KillCipher {
                    kc1: pre.kc1,
                    kc2: ElgamalCipher {
                        c1: pre.kc2.c1,
                        c2: pre.kc2.c2 - pre.kc2.c1 * psk
                    },
                    kc3: pre.kc3
                };
            } else { // decrypt the last row, the final message if still protected by rpk_witch
                return KillCipher {
                    kc1: pre.kc1,
                    kc2: pre.kc2,
                    kc3: ElgamalCipher{
                        c1: pre.kc3.c1,
                        c2: pre.kc3.c2 - pre.kc3.c1 * psk
                    }
                };
            }
        }
    }

    transition witch_see_victim(
        rsk: scalar,
        public c: ElgamalCipher
    ) -> group {
        return c.c2 - c.c1 * rsk;
    }
}
