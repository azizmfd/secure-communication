import re
import unicodedata

# Texte français de référence : sert uniquement à calculer des statistiques
# (fréquence des paires de lettres). Ce n'est pas le message attaqué.
REFERENCE_TEXT = """
Le matin, la ville se réveille doucement. Les boulangers sortent les premiers pains du four et l'odeur
se répand dans les rues encore calmes. Les enfants partent à l'école avec leurs cartables, tandis que
les adultes se dépêchent de prendre le bus ou le tramway pour arriver à l'heure au travail. Dans les
cafés, les clients lisent le journal en buvant un thé chaud et parlent de la météo, du football et des
projets de vacances. Pendant ce temps, le soleil monte lentement derrière les immeubles et réchauffe
les terrasses. Au marché, les marchands installent leurs étals et vantent la fraîcheur de leurs fruits
et de leurs légumes. On y trouve des tomates, des oranges, du poisson et toutes sortes d'épices dont
les parfums attirent les passants.

L'histoire de notre pays est longue et riche. Pendant des siècles, des peuples très différents se sont
rencontrés, ont commercé, se sont parfois affrontés, mais ils ont aussi appris les uns des autres. Les
savants ont étudié les étoiles, les mathématiques et la médecine, et leurs livres ont voyagé de ville en
ville. Aujourd'hui encore, nous profitons de ces découvertes sans toujours nous en rendre compte. Chaque
génération construit sur le travail de celle qui la précède, et c'est ainsi que les connaissances
progressent. Il est important de transmettre ce savoir aux jeunes, car ils auront à relever les défis de
demain.

La technologie a profondément changé notre manière de vivre. Il y a quelques années à peine, il fallait
se déplacer pour envoyer une lettre ou consulter un livre ; maintenant, une simple connexion suffit pour
discuter avec une personne qui se trouve à l'autre bout du monde. Cependant, ces progrès apportent aussi
des risques : nos informations personnelles circulent beaucoup plus facilement, et il faut apprendre à
les protéger. Un mot de passe solide, une mise à jour régulière et un peu de prudence permettent déjà
d'éviter la plupart des problèmes. Les entreprises doivent également former leurs employés, car une
seule erreur peut avoir de lourdes conséquences pour tout le monde.

Dans la nature, chaque saison apporte ses couleurs. Au printemps, les arbres se couvrent de fleurs et les
oiseaux reviennent chanter dans les jardins. L'été est chaud et sec, les journées sont longues et les
soirées agréables. En automne, les feuilles tombent doucement et la forêt prend des teintes rouges et
dorées. L'hiver, enfin, apporte le froid et parfois la neige, qui recouvre les montagnes d'un grand
manteau blanc. Les agriculteurs observent le ciel avec attention, car de la pluie ou du soleil dépend
toute la récolte de l'année. Ils savent que la terre demande du temps, de la patience et beaucoup de
respect.
"""

# Mots français très fréquents (liste générale, volontairement sans rapport avec le message attaqué)
WORDS = set("""
le la les un une des du de et en à au aux que qui quoi dans par pour sur avec sans sous ce cet cette
ces se sa son ses ma mon mes ta ton tes notre nos votre vos leur leurs il elle ils elles on nous vous
je tu me te lui y ne pas plus moins très mais ou où donc car ni si est sont était être a ont avoir fait
faire peut peuvent tout tous toute toutes comme aussi bien encore déjà après avant depuis pendant entre
vers chez contre ainsi alors puis quand pourquoi comment cela ça celui ceux même autre autres deux trois
premier nouveau nouvelle grand grande petit petite pays temps jour jours monde vie homme hommes fois cas
partie rien aucun chaque quelque quelques peu beaucoup trop assez toujours jamais souvent parfois
aujourd hui hier demain ici là où dont lequel laquelle lesquels
""".split())


def strip_accents(text):
    """é -> e, à -> a, ... (pour les statistiques)."""
    return "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")


def normalized_letters(text):
    """Lettres A-Z uniquement, sans accents, en majuscules."""
    return re.sub(r"[^A-Z]", "", strip_accents(text).upper())


def build_bigram_log_probs():
    letters = normalized_letters(REFERENCE_TEXT)
    counts = {}
    for a, b in zip(letters, letters[1:]):
        counts[a + b] = counts.get(a + b, 0) + 1
    total = len(letters) - 1
    # lissage : une paire jamais vue reçoit une petite probabilité
    import math
    log_probs = {}
    for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            log_probs[a + b] = math.log((counts.get(a + b, 0) + 0.5) / (total + 0.5 * 676))
    return log_probs


BIGRAM_LOG = build_bigram_log_probs()
