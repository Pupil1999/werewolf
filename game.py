from run_leo.core import import_leo_program
from run_leo import Account
import random

# Check the 
def check_end(game, rpk_list, rsks, pk, psks) -> (bool, bool, bool):
    camp_stat = game.statistic_init()
    for rsk in rsks:
        r = random.getrandbits(253)
        er_1 = random.getrandbits(253)
        er_2 = random.getrandbits(253)
        er_3 = random.getrandbits(253)

        camp_stat = game.statistic_survivors(
            True,
            rsk,
            rpk_list,
            r,
            er_1,
            er_2,
            er_3,
            pk,
            0,
            camp_stat
        )
    
    for psk in psks:
        camp_stat = game.statistic_survivors(
            False,
            0,
            rpk_list,
            0,
            0,
            0,
            0,
            0,
            psk,
            camp_stat
        )
    
    return (
        camp_stat.wolf.c2 != 0,
        camp_stat.villager.c2 != 0,
        camp_stat.psychic.c2 != 0
    )

# ch: from 1 to 12
def check_role(game, rsks, rpk_list, ch, rsk_seer):
    rands = []
    for _ in range(12):
        rands.append(random.getrandbits(253))

    check_role_list = game.check_role_init(
        rands[0], rands[1], rands[2], rands[3],
        rands[4], rands[5], rands[6], rands[7],
        rands[8], rands[9], rands[10], rands[11],
        )
    
    for rsk in rsks:
        rs = []
        for _ in range(12):
            rs.append(random.getrandbits(253))
        rss = game.gen_twelve_rands(
            rs[0], rs[1], rs[2], rs[3],
            rs[4], rs[5], rs[6], rs[7],
            rs[8], rs[9], rs[10], rs[11],
            )

        r = random.getrandbits(253)
        check_role_list = game.rerand(
            True,
            rpk_list,
            rsk,
            ch,
            check_role_list,
            rss,
            r,
            0,
            0
            )
    
    #c = check_role_list.p3
    #plain = game.dec_check_role(rsk_seer, c)
    #print(plain)
    
    index = 1
    null_rands = game.gen_twelve_rands(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for rsk in rsks:
        check_role_list = game.rerand(
            False,
            rpk_list,
            rsk,
            ch,
            check_role_list,
            null_rands,
            0,
            index,
            random.getrandbits(253)
        )
        index += 1

    attr = "p" + str(ch)
    return game.dec_check_role(rsk_seer, getattr(check_role_list, attr))


def kill_at_night(game, pk, psks, rsks, ppk_v, ppk_p, rpks, rpk_wolf, rpk_witch):
    kill_list = game.kill_init()
    for rsk in rsks:
        kill_list = game.kill_vote(
            pk,
            rsk,
            ppk_v,
            ppk_p,
            rpks,
            rpk_wolf,
            random.getrandbits(253),
            random.getrandbits(253),
            random.getrandbits(253),
            rpk_witch,
            kill_list
        )

    # decrease the second row with the first row
    kill_list = game.dec_kill_vote(kill_list, 0, 0, True, 0, 0, 0, False, 0)

    # add entrophy to the cipher
    for _ in psks:
        kill_list = game.dec_kill_vote(
            kill_list,
            0,
            2,
            False,
            random.getrandbits(253),
            0,
            0,
            False,
            0
        )
    # 
    for psk in psks:
        kill_list = game.dec_kill_vote(
            kill_list,
            psk,
            3, # decrypting the second row
            False,
            0,
            0,
            0,
            False,
            0
        )
    # check if there is someone killed
    if(kill_list.kc2.c2 == 0):
        return 0

    for psk in psks:
        kill_list = game.dec_kill_vote(
            kill_list,
            psk,
            1,
            False,
            random.getrandbits(253),
            0,
            2,
            False,
            0
        )
    return kill_list.kc1.c2


if __name__ == "__main__":
    # We simulate the game process using only one account
    game = import_leo_program(".")()
    account = Account(
        private_key='APrivateKey1zkpFgvnNWJsTC4bxqmy6ANRsHQ2FJ8DAJAd4Ep7uPR8N6cx'
    )
    game.set_account(account)

    # Used to denote the roles, but the link between roles and players are not known.
    role_pks = []
    role_sks = []


    # Used to communicate with each other, the 
    # link between public keys and players are known.
    role_ppks = []
    role_psks = []
    print("==========Game Start==========")
    print("Generating roles...")
    roles = []
    for i in range(1, 13):
        rsk = random.getrandbits(253)
        rpk = game.elgamal_key_gen(rsk)
        role_sks.append(rsk)
        role_pks.append(rpk)

        psk = random.getrandbits(253)
        ppk = game.elgamal_key_gen(rsk)
        role_psks.append(rsk)
        role_ppks.append(rpk)

    pk = game.aggregate_public_keys(
        role_ppks[0], role_ppks[1], role_ppks[2], role_ppks[3],
        role_ppks[4], role_ppks[5], role_ppks[6], role_ppks[7],
        role_ppks[8], role_ppks[9], role_ppks[10], role_ppks[11],
        )

    for i in range(1, 13):
        r = random.getrandbits(253)
        role_list_item = game.elgamal_enc(role_pks[i-1], pk, r)
        roles.append(role_list_item)

    # Get a role list waiting for shuffling
    role_list = game.gen_role_list(
        roles[0], roles[1], roles[2], roles[3],
        roles[4], roles[5], roles[6], roles[7],
        roles[8], roles[9], roles[10], roles[11],
        )

    sr = []
    for i in range(0, 12):
        srr = random.getrandbits(253)
        sr.append(srr)
    shuffled_role_list = game.shuffle(
        role_list,
        pk,
        sr[0], sr[1], sr[2], sr[3],
        sr[4], sr[5], sr[6], sr[7],
        sr[8], sr[9], sr[10], sr[11],
    )

    for i in range(0, 12):
        decrypted_list = game.dec_shuffled_list(
            shuffled_role_list,
            role_psks[i]
            )
        shuffled_role_list = decrypted_list
        
    #print("==========")
    #print(role_pks)
    #print("==========")
    #print(decrypted_list)

    rpks = []
    rpks.append(decrypted_list.l1.c2)
    rpks.append(decrypted_list.l2.c2)
    rpks.append(decrypted_list.l3.c2)
    rpks.append(decrypted_list.l4.c2)
    rpks.append(decrypted_list.l5.c2)
    rpks.append(decrypted_list.l6.c2)
    rpks.append(decrypted_list.l7.c2)
    rpks.append(decrypted_list.l8.c2)
    rpks.append(decrypted_list.l9.c2)
    rpks.append(decrypted_list.l10.c2)
    rpks.append(decrypted_list.l11.c2)
    rpks.append(decrypted_list.l12.c2)
    #print("==========")
    #print(rpks)
    #print("==========")

    #for i in range(0, 12):
    #    npk = game.elgamal_key_gen(role_sks[i])
    #    print(npk)

    print("==========Roles generated!==========")
    aleo_public_role_keys = game.gen_public_role_keys_list(
        rpks[0], rpks[1], rpks[2], rpks[3],
        rpks[4], rpks[5], rpks[6], rpks[7],
        rpks[8], rpks[9], rpks[10], rpks[11]
        )
    #print(aleo_public_role_keys)

    #b1, b2, b3 = check_end(game, aleo_public_role_keys, role_sks[5:7], pk, role_psks)
    #print(b1, b2, b3)

    #id = check_role(game, role_sks, aleo_public_role_keys, 3, role_sks[8])
    #print(id)

    #is_killed = kill_at_night(game, pk, role_psks, role_sks, role_ppks[0], 
    #           role_ppks[2], aleo_public_role_keys, role_pks[2], role_pks[9])
    #print(is_killed)
    #print(role_ppks[0])

    rsk_seer = role_sks[8]
    rpk_witch = role_pks[9]
    print("==========Night Comes! Wolves Awake!==========")
    while(True):
        inp1, inp2 = 0, 0
        while(True):
            inp1 = input("\"Select a victim, wolves!\"\n")
            try:
                inp1 = int(inp1)
                if (inp1 >= 1 and inp1 <= len(role_pks)):
                    break
            except ValueError:
                print("Invalid input, select a number that denoting the player.")

        while(True):
            inp2 = input("\"Select a player that the protector want to give a shield!\"\n")
            try:
                inp2 = int(inp2)
                if (inp2 >= 1 and inp2 <= len(role_pks)):
                    break
            except ValueError:
                print("Invalid input, select a number that denoting the player.")

        print("Computing the victim, please wait.....")
        victim = kill_at_night(game, pk, role_psks, role_sks, role_ppks[inp1 - 1],
                role_ppks[inp2 - 1], aleo_public_role_keys, role_pks[2], rpk_witch)
        print("==========The victim tonight is:==========")
        if(victim == 0):
            print("No victim tonight")
        else:
            pk = game.dec_public_key(pk, victim)
            role_ppks.pop(inp1 - 1)
            role_psks.pop(inp1 - 1)
            role_pks.pop(inp1 - 1)
            role_sks.pop(inp1 - 1)
            print("Victim is: Player" + str(inp1 - 1))

        print("==========Checking the survivors of each camp==========")
        camp1, camp2, camp3 = check_end(game, aleo_public_role_keys, role_sks, pk, role_psks)
        if(camp2 == False or camp3 == False):
            print("Wolves Win!")
            break
        elif(camp1 == False):
            print("Villagers and Psychics Win!")
            break
        else:
            print("No Camps Eliminated, Game Continues!")

        if(str(input("Do you want to check the role" 
                     "of some player? It's supposed to take 2min. y/n\n"))=="y"):
            while(True):
                try:
                    inp3 = int(input("Select a player that you want to check.\n"))
                    if(inp3 >= 1 and inp3 <= len(role_pks)):
                        break
                except ValueError:
                    print("Wrong index of players")
            id = check_role(game, role_sks, aleo_public_role_keys, inp3, rsk_seer)
            if(id):
                print("The checked player is wolf.")
            else:
                print("The checked player is not a wolf.")